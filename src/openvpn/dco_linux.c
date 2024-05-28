/*
 *  Interface to linux dco networking code
 *
 *  Copyright (C) 2020-2024 Antonio Quartulli <a@unstable.cc>
 *  Copyright (C) 2020-2024 Arne Schwabe <arne@rfc2549.org>
 *  Copyright (C) 2020-2024 OpenVPN Inc <sales@openvpn.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#if defined(ENABLE_DCO) && defined(TARGET_LINUX)

#include "syshead.h"

#include "dco_linux.h"
#include "errlevel.h"
#include "buffer.h"
#include "networking.h"
#include "openvpn.h"

#include "socket.h"
#include "tun.h"
#include "ssl.h"
#include "fdmisc.h"
#include "multi.h"
#include "ssl_verify.h"

#include "ovpn_dco_linux.h"

#include <netlink/socket.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>


static int
do_family_name_resolve(struct nl_sock *nl_sock, int msglevel, const char *family_name,
                       dco_context_t *dco, const struct dco_ops *ops)
{
    int ret = genl_ctrl_resolve(nl_sock, family_name);

    if (ret < 0)
    {
        msg(msglevel, "Cannot find %s netlink component: %s", family_name, nl_geterror(ret));
    }

    if (dco)
    {
        /* Ensures that we will use the proper ops for the dco version available */
        dco->ops = ops;
    }

    return ret;
}

int
resolve_ovpn_netlink_id(int msglevel, dco_context_t *dco)
{
    int ret;
    struct nl_sock *nl_sock = nl_socket_alloc();

    if (!nl_sock)
    {
        msg(msglevel, "Allocating net link socket failed");
        return -ENOMEM;
    }

    ret = genl_connect(nl_sock);
    if (ret)
    {
        msg(msglevel, "Cannot connect to generic netlink: %s",
            nl_geterror(ret));
        goto err_sock;
    }
    set_cloexec(nl_socket_get_fd(nl_sock));

    ret = do_family_name_resolve(nl_sock, msglevel, OVPN_NL_NAME, dco, &dco_ops_v2);

err_sock:
    nl_socket_free(nl_sock);
    return ret;
}

int
ovpn_nl_recvmsgs(dco_context_t *dco, const char *prefix)
{
    int ret = nl_recvmsgs(dco->nl_sock, dco->nl_cb);

    switch (ret)
    {
        case -NLE_INTR:
            msg(M_WARN, "%s: netlink received interrupt due to signal - ignoring", prefix);
            break;

        case -NLE_NOMEM:
            msg(M_ERR, "%s: netlink out of memory error", prefix);
            break;

        case -M_ERR:
            msg(M_WARN, "%s: netlink reports blocking read - aborting wait", prefix);
            break;

        case -NLE_NODEV:
            msg(M_ERR, "%s: netlink reports device not found:", prefix);
            break;

        case -NLE_OBJ_NOTFOUND:
            msg(M_INFO, "%s: netlink reports object not found, ovpn-dco unloaded?", prefix);
            break;

        default:
            if (ret)
            {
                msg(M_NONFATAL, "%s: netlink reports error (%d): %s", prefix, ret, nl_geterror(-ret));
            }
            break;
    }

    return ret;
}

int
ovpn_nl_msg_send(dco_context_t *dco, struct nl_msg *nl_msg, ovpn_nl_cb cb,
                 void *cb_arg, const char *prefix)
{
    dco->status = 1;

    nl_cb_set(dco->nl_cb, NL_CB_VALID, NL_CB_CUSTOM, cb, cb_arg);
    nl_send_auto(dco->nl_sock, nl_msg);

    while (dco->status == 1)
    {
        ovpn_nl_recvmsgs(dco, prefix);
    }

    if (dco->status < 0)
    {
        msg(M_INFO, "%s: failed to send netlink message: %s (%d)",
            prefix, strerror(-dco->status), dco->status);
    }

    return dco->status;
}

struct sockaddr *
mapped_v4_to_v6(struct sockaddr *sock, struct gc_arena *gc)
{
    struct sockaddr_in6 *sock6 = (struct sockaddr_in6 *)sock;
    if (sock->sa_family == AF_INET6 && IN6_IS_ADDR_V4MAPPED(&sock6->sin6_addr))
    {

        struct sockaddr_in *sock4;
        ALLOC_OBJ_CLEAR_GC(sock4, struct sockaddr_in, gc);
        memcpy(&sock4->sin_addr, sock6->sin6_addr.s6_addr + 12, 4);
        sock4->sin_port = sock6->sin6_port;
        sock4->sin_family = AF_INET;
        return (struct sockaddr *)sock4;
    }
    return sock;
}

int
ovpn_nl_cb_finish(struct nl_msg (*msg) __attribute__ ((unused)), void *arg)
{
    int *status = arg;

    *status = 0;
    return NL_SKIP;
}

int
ovpn_nl_cb_error(struct sockaddr_nl (*nla) __attribute__ ((unused)),
                 struct nlmsgerr *err, void *arg)
{
    struct nlmsghdr *nlh = (struct nlmsghdr *)err - 1;
    struct nlattr *tb_msg[NLMSGERR_ATTR_MAX + 1];
    int len = nlh->nlmsg_len;
    struct nlattr *attrs;
    int *ret = arg;
    int ack_len = sizeof(*nlh) + sizeof(int) + sizeof(*nlh);

    *ret = err->error;

    if (!(nlh->nlmsg_flags & NLM_F_ACK_TLVS))
    {
        return NL_STOP;
    }

    if (!(nlh->nlmsg_flags & NLM_F_CAPPED))
    {
        ack_len += err->msg.nlmsg_len - sizeof(*nlh);
    }

    if (len <= ack_len)
    {
        return NL_STOP;
    }

    attrs = (void *)((unsigned char *)nlh + ack_len);
    len -= ack_len;

    nla_parse(tb_msg, NLMSGERR_ATTR_MAX, attrs, len, NULL);
    if (tb_msg[NLMSGERR_ATTR_MSG])
    {
        len = strnlen((char *)nla_data(tb_msg[NLMSGERR_ATTR_MSG]),
                      nla_len(tb_msg[NLMSGERR_ATTR_MSG]));
        msg(M_WARN, "kernel error: %*s\n", len,
            (char *)nla_data(tb_msg[NLMSGERR_ATTR_MSG]));
    }

    return NL_STOP;
}

void
ovpn_dco_init_netlink(dco_context_t *dco)
{
    struct gc_arena gc = gc_new();
    if (!dco->ops)
    {
        ALLOC_OBJ_CLEAR_GC(dco->ops, struct dco_ops, &gc);
    }

    dco->ovpn_dco_id = resolve_ovpn_netlink_id(M_ERR, dco);

    dco->nl_sock = nl_socket_alloc();

    if (!dco->nl_sock)
    {
        msg(M_ERR, "Cannot create netlink socket");
    }

    int ret = genl_connect(dco->nl_sock);
    if (ret)
    {
        msg(M_ERR, "Cannot connect to generic netlink: %s",
            nl_geterror(ret));
    }

    /* set close on exec and non-block on the netlink socket */
    set_cloexec(nl_socket_get_fd(dco->nl_sock));
    set_nonblock(nl_socket_get_fd(dco->nl_sock));

    dco->nl_cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!dco->nl_cb)
    {
        msg(M_ERR, "failed to allocate netlink callback");
    }

    nl_socket_set_cb(dco->nl_sock, dco->nl_cb);

    nl_cb_err(dco->nl_cb, NL_CB_CUSTOM, ovpn_nl_cb_error, &dco->status);
    nl_cb_set(dco->nl_cb, NL_CB_FINISH, NL_CB_CUSTOM, ovpn_nl_cb_finish,
              &dco->status);
    nl_cb_set(dco->nl_cb, NL_CB_ACK, NL_CB_CUSTOM, ovpn_nl_cb_finish,
              &dco->status);

    /* The async PACKET messages confuse libnl and it will drop them with
     * wrong sequence numbers (NLE_SEQ_MISMATCH), so disable libnl's sequence
     * number check */
    nl_socket_disable_seq_check(dco->nl_sock);

    /* nl library sets the buffer size to 32k/32k by default which is sometimes
     * overrun with very fast connecting/disconnecting clients.
     * TODO: fix this in a better and more reliable way */
    ASSERT(!nl_socket_set_buffer_size(dco->nl_sock, 1024*1024, 1024*1024));
    gc_free(&gc);
}

bool
ovpn_dco_init(int mode, dco_context_t *dco)
{
    switch (mode)
    {
        case CM_TOP:
            dco->ifmode = OVPN_V2_MODE_MP;
            break;

        case CM_P2P:
            dco->ifmode = OVPN_V2_MODE_P2P;
            break;

        default:
            ASSERT(false);
    }

    ovpn_dco_init_netlink(dco);
    return true;
}

void
ovpn_dco_uninit_netlink(dco_context_t *dco)
{
    nl_socket_free(dco->nl_sock);
    dco->nl_sock = NULL;

    /* Decrease reference count */
    nl_cb_put(dco->nl_cb);

    CLEAR(dco);
}

void
ovpn_dco_register(dco_context_t *dco)
{
    msg(D_DCO_DEBUG, __func__);
    ovpn_get_mcast_id(dco);

    if (dco->ovpn_dco_mcast_id < 0)
    {
        msg(M_ERR, "cannot get mcast group: %s",  nl_geterror(dco->ovpn_dco_mcast_id));
    }

    /* Register for ovpn-dco specific multicast messages that the kernel may
     * send
     */
    int ret = nl_socket_add_membership(dco->nl_sock, dco->ovpn_dco_mcast_id);
    if (ret)
    {
        msg(M_ERR, "%s: failed to join groups: %d", __func__, ret);
    }
}

int
open_tun_dco(struct tuntap *tt, openvpn_net_ctx_t *ctx, const char *dev)
{
    int ret = tt->dco.ops->open_tun_dco(tt, ctx, dev);
    return ret;
}

int
mcast_family_handler(struct nl_msg *msg, void *arg)
{
    dco_context_t *dco = arg;
    struct nlattr *tb[CTRL_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));

    nla_parse(tb, CTRL_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
              genlmsg_attrlen(gnlh, 0), NULL);

    if (!tb[CTRL_ATTR_MCAST_GROUPS])
    {
        return NL_SKIP;
    }

    struct nlattr *mcgrp;
    int rem_mcgrp;
    nla_for_each_nested(mcgrp, tb[CTRL_ATTR_MCAST_GROUPS], rem_mcgrp)
    {
        struct nlattr *tb_mcgrp[CTRL_ATTR_MCAST_GRP_MAX + 1];

        nla_parse(tb_mcgrp, CTRL_ATTR_MCAST_GRP_MAX,
                  nla_data(mcgrp), nla_len(mcgrp), NULL);

        if (!tb_mcgrp[CTRL_ATTR_MCAST_GRP_NAME]
            || !tb_mcgrp[CTRL_ATTR_MCAST_GRP_ID])
        {
            continue;
        }

        if (strncmp(nla_data(tb_mcgrp[CTRL_ATTR_MCAST_GRP_NAME]),
                    OVPN_NL_MULTICAST_GROUP_PEERS,
                    nla_len(tb_mcgrp[CTRL_ATTR_MCAST_GRP_NAME])) != 0)
        {
            continue;
        }
        dco->ovpn_dco_mcast_id = nla_get_u32(tb_mcgrp[CTRL_ATTR_MCAST_GRP_ID]);
        break;
    }

    return NL_SKIP;
}

int
ovpn_get_mcast_id(dco_context_t *dco)
{
    dco->ovpn_dco_mcast_id = -ENOENT;

    /* Even though 'nlctrl' is a constant, there seem to be no library
     * provided define for it */
    int ctrlid = genl_ctrl_resolve(dco->nl_sock, "nlctrl");

    struct nl_msg *nl_msg = nlmsg_alloc();
    if (!nl_msg)
    {
        return -ENOMEM;
    }

    genlmsg_put(nl_msg, 0, 0, ctrlid, 0, 0, CTRL_CMD_GETFAMILY, 0);

    int ret = -EMSGSIZE;
    NLA_PUT_STRING(nl_msg, CTRL_ATTR_FAMILY_NAME, OVPN_NL_NAME);

    ret = ovpn_nl_msg_send(dco, nl_msg, mcast_family_handler, dco, __func__);

nla_put_failure:
    nlmsg_free(nl_msg);
    return ret;
}

bool
dco_available(int msglevel, dco_context_t *dco)
{
    if (resolve_ovpn_netlink_id(D_DCO_DEBUG, dco) < 0)
    {
        msg(msglevel,
            "Note: Kernel support for ovpn-dco missing, disabling data channel offload.");
        return false;
    }
    return true;
}

const char *
dco_version_string(struct gc_arena *gc)
{
    struct buffer out = alloc_buf_gc(256, gc);
    FILE *fp = fopen("/sys/module/ovpn_dco_v2/version", "r");
    if (!fp)
    {
        return "N/A";
    }

    if (!fgets(BSTR(&out), BCAP(&out), fp))
    {
        fclose(fp);
        return "ERR";
    }

    /* remove potential newline at the end of the string */
    char *str = BSTR(&out);
    char *nl = strchr(str, '\n');
    if (nl)
    {
        *nl = '\0';
    }

    fclose(fp);
    return BSTR(&out);
}

int
dco_new_peer(dco_context_t *dco, unsigned int peerid, int sd,
             struct sockaddr *localaddr, struct sockaddr *remoteaddr,
             struct in_addr *remote_in4, struct in6_addr *remote_in6)
{
    int ret = dco->ops->dco_new_peer(dco, peerid, sd, localaddr, remoteaddr, remote_in4, remote_in6);
    return ret;
}

void
close_tun_dco(struct tuntap *tt, openvpn_net_ctx_t *ctx)
{
    tt->dco.ops->close_tun_dco(tt, ctx);
}

int
dco_swap_keys(dco_context_t *dco, unsigned int peerid)
{
    int ret = dco->ops->dco_swap_keys(dco, peerid);
    return ret;
}


int
dco_del_peer(dco_context_t *dco, unsigned int peerid)
{
    int ret = dco->ops->dco_del_peer(dco, peerid);
    return ret;
}


int
dco_del_key(dco_context_t *dco, unsigned int peerid,
            dco_key_slot_t slot)
{
    int ret = dco->ops->dco_del_key(dco, peerid, slot);
    return ret;
}

int
dco_new_key(dco_context_t *dco, unsigned int peerid, int keyid,
            dco_key_slot_t slot,
            const uint8_t *encrypt_key, const uint8_t *encrypt_iv,
            const uint8_t *decrypt_key, const uint8_t *decrypt_iv,
            const char *ciphername)
{
    int ret = dco->ops->dco_new_key(dco, peerid, keyid, slot, encrypt_key, encrypt_iv, decrypt_key, decrypt_iv, ciphername);
    return ret;
}

int
dco_set_peer(dco_context_t *dco, unsigned int peerid,
             int keepalive_interval, int keepalive_timeout, int mss)
{
    int ret = dco->ops->dco_set_peer(dco, peerid, keepalive_interval, keepalive_timeout, mss);
    return ret;
}

void
process_incoming_dco_actual(struct context *c)
{
    c->c1.tuntap->dco.ops->process_incoming_dco(c);
}

int
dco_do_read(dco_context_t *dco)
{
    int ret = dco->ops->dco_do_read(dco);
    return ret;
}

int
dco_parse_peer_multi(struct nl_msg *msg, void *arg)
{
    struct multi_context *m = arg;
    int ret = m->top.c1.tuntap->dco.ops->dco_parse_peer_multi(msg, arg);

    return ret;
}

int
dco_get_peer_stats_multi(dco_context_t *dco, struct multi_context *m)
{
    int ret = dco->ops->dco_get_peer_stats_multi(dco, m);
    return ret;
}

int
dco_get_peer_stats(struct context *c)
{
    int ret = c->c1.tuntap->dco.ops->dco_get_peer_stats(c);
    return ret;
}

void
dco_event_set(dco_context_t *dco, struct event_set *es, void *arg)
{
    if (dco && dco->nl_sock)
    {
        event_ctl(es, nl_socket_get_fd(dco->nl_sock), EVENT_READ, arg);
    }
}

const char *
dco_get_supported_ciphers()
{
    return "AES-128-GCM:AES-256-GCM:AES-192-GCM:CHACHA20-POLY1305";
}

#endif /* defined(ENABLE_DCO) && defined(TARGET_LINUX) */
