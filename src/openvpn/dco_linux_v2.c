/*
 *  Interface to linux dco networking code
 *
 *  Copyright (C) 2020-2024 Antonio Quartulli <a@unstable.cc>
 *  Copyright (C) 2020-2024 Arne Schwabe <arne@rfc2549.org>
 *  Copyright (C) 2020-2024 Gianmarco De Gregori <gianmarco@mandelbit.com>
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

int
open_tun_dco_v2(struct tuntap *tt, openvpn_net_ctx_t *ctx, const char *dev)
{
    msg(D_DCO_DEBUG, "%s: %s", __func__, dev);
    ASSERT(tt->type == DEV_TYPE_TUN);

    int ret = net_iface_new(ctx, dev, "ovpn-dco", &tt->dco);
    if (ret < 0)
    {
        msg(D_DCO_DEBUG, "Cannot create DCO interface %s: %d", dev, ret);
        return ret;
    }

    tt->dco.ifindex = if_nametoindex(dev);
    if (!tt->dco.ifindex)
    {
        msg(M_FATAL, "DCO: cannot retrieve ifindex for interface %s", dev);
    }

    tt->dco.dco_message_peer_id = -1;

    ovpn_dco_register(&tt->dco);

    return 0;
}

static struct nl_msg *
ovpn_dco_v2_nlmsg_create(dco_context_t *dco, int cmd)
{
    enum ovpn_v2_nl_commands enum_cmd = (enum ovpn_v2_nl_commands)cmd;
    struct nl_msg *nl_msg = nlmsg_alloc();
    if (!nl_msg)
    {
        msg(M_ERR, "cannot allocate netlink message");
        return NULL;
    }

    genlmsg_put(nl_msg, 0, 0, dco->ovpn_dco_id, 0, 0, enum_cmd, 0);
    NLA_PUT_U32(nl_msg, OVPN_V2_ATTR_IFINDEX, dco->ifindex);

    return nl_msg;
nla_put_failure:
    nlmsg_free(nl_msg);
    msg(M_INFO, "cannot put into netlink message");
    return NULL;
}

int
dco_v2_new_peer(dco_context_t *dco, unsigned int peerid, int sd,
                struct sockaddr *localaddr, struct sockaddr *remoteaddr,
                struct in_addr *remote_in4, struct in6_addr *remote_in6)
{
    struct gc_arena gc = gc_new();
    const char *remotestr = "[undefined]";
    if (remoteaddr)
    {
        remotestr = print_sockaddr(remoteaddr, &gc);
    }
    msg(D_DCO_DEBUG, "%s: peer-id %d, fd %d, remote addr: %s", __func__,
        peerid, sd, remotestr);

    struct nl_msg *nl_msg = ovpn_dco_v2_nlmsg_create(dco, OVPN_V2_CMD_NEW_PEER);
    struct nlattr *attr = nla_nest_start(nl_msg, OVPN_V2_ATTR_NEW_PEER);
    int ret = -EMSGSIZE;

    NLA_PUT_U32(nl_msg, OVPN_V2_NEW_PEER_ATTR_PEER_ID, peerid);
    NLA_PUT_U32(nl_msg, OVPN_V2_NEW_PEER_ATTR_SOCKET, sd);

    /* Set the remote endpoint if defined (for UDP) */
    if (remoteaddr)
    {
        remoteaddr = mapped_v4_to_v6(remoteaddr, &gc);
        int alen = af_addr_size(remoteaddr->sa_family);

        NLA_PUT(nl_msg, OVPN_V2_NEW_PEER_ATTR_SOCKADDR_REMOTE, alen, remoteaddr);
    }

    if (localaddr)
    {
        localaddr = mapped_v4_to_v6(localaddr, &gc);
        if (localaddr->sa_family == AF_INET)
        {
            NLA_PUT(nl_msg, OVPN_V2_NEW_PEER_ATTR_LOCAL_IP, sizeof(struct in_addr),
                    &((struct sockaddr_in *)localaddr)->sin_addr);
        }
        else if (localaddr->sa_family == AF_INET6)
        {
            NLA_PUT(nl_msg, OVPN_V2_NEW_PEER_ATTR_LOCAL_IP, sizeof(struct in6_addr),
                    &((struct sockaddr_in6 *)localaddr)->sin6_addr);
        }
    }

    /* Set the primary VPN IP addresses of the peer */
    if (remote_in4)
    {
        NLA_PUT_U32(nl_msg, OVPN_V2_NEW_PEER_ATTR_IPV4, remote_in4->s_addr);
    }
    if (remote_in6)
    {
        NLA_PUT(nl_msg, OVPN_V2_NEW_PEER_ATTR_IPV6, sizeof(struct in6_addr),
                remote_in6);
    }
    nla_nest_end(nl_msg, attr);

    ret = ovpn_nl_msg_send(dco, nl_msg, NULL, NULL, __func__);

nla_put_failure:
    nlmsg_free(nl_msg);
    gc_free(&gc);
    return ret;
}

void
close_tun_dco_v2(struct tuntap *tt, openvpn_net_ctx_t *ctx)
{
    msg(D_DCO_DEBUG, __func__);

    net_iface_del(ctx, tt->actual_name);
    ovpn_dco_uninit_netlink(&tt->dco);
}

int
dco_v2_swap_keys(dco_context_t *dco, unsigned int peerid)
{
    msg(D_DCO_DEBUG, "%s: peer-id %d", __func__, peerid);

    struct nl_msg *nl_msg = ovpn_dco_v2_nlmsg_create(dco, OVPN_V2_CMD_SWAP_KEYS);
    if (!nl_msg)
    {
        return -ENOMEM;
    }

    struct nlattr *attr = nla_nest_start(nl_msg, OVPN_V2_ATTR_SWAP_KEYS);
    int ret = -EMSGSIZE;
    NLA_PUT_U32(nl_msg, OVPN_V2_SWAP_KEYS_ATTR_PEER_ID, peerid);
    nla_nest_end(nl_msg, attr);

    ret = ovpn_nl_msg_send(dco, nl_msg, NULL, NULL, __func__);

nla_put_failure:
    nlmsg_free(nl_msg);
    return ret;
}


int
dco_v2_del_peer(dco_context_t *dco, unsigned int peerid)
{
    msg(D_DCO_DEBUG, "%s: peer-id %d", __func__, peerid);

    struct nl_msg *nl_msg = ovpn_dco_v2_nlmsg_create(dco, OVPN_V2_CMD_DEL_PEER);
    if (!nl_msg)
    {
        return -ENOMEM;
    }

    struct nlattr *attr = nla_nest_start(nl_msg, OVPN_V2_ATTR_DEL_PEER);
    int ret = -EMSGSIZE;
    NLA_PUT_U32(nl_msg, OVPN_V2_DEL_PEER_ATTR_PEER_ID, peerid);
    nla_nest_end(nl_msg, attr);

    ret = ovpn_nl_msg_send(dco, nl_msg, NULL, NULL, __func__);

nla_put_failure:
    nlmsg_free(nl_msg);
    return ret;
}


int
dco_v2_del_key(dco_context_t *dco, unsigned int peerid,
               dco_key_slot_t slot)
{
    msg(D_DCO_DEBUG, "%s: peer-id %d, slot %d", __func__, peerid, slot);

    struct nl_msg *nl_msg = ovpn_dco_v2_nlmsg_create(dco, OVPN_V2_CMD_DEL_KEY);
    if (!nl_msg)
    {
        return -ENOMEM;
    }

    struct nlattr *attr = nla_nest_start(nl_msg, OVPN_V2_ATTR_DEL_KEY);
    int ret = -EMSGSIZE;
    NLA_PUT_U32(nl_msg, OVPN_V2_DEL_KEY_ATTR_PEER_ID, peerid);
    NLA_PUT_U8(nl_msg, OVPN_V2_DEL_KEY_ATTR_KEY_SLOT, slot);
    nla_nest_end(nl_msg, attr);

    ret = ovpn_nl_msg_send(dco, nl_msg, NULL, NULL, __func__);

nla_put_failure:
    nlmsg_free(nl_msg);
    return ret;
}

int
dco_v2_new_key(dco_context_t *dco, unsigned int peerid, int keyid,
               dco_key_slot_t slot,
               const uint8_t *encrypt_key, const uint8_t *encrypt_iv,
               const uint8_t *decrypt_key, const uint8_t *decrypt_iv,
               const char *ciphername)
{
    msg(D_DCO_DEBUG, "%s: slot %d, key-id %d, peer-id %d, cipher %s",
        __func__, slot, keyid, peerid, ciphername);

    const size_t key_len = cipher_kt_key_size(ciphername);
    const int nonce_tail_len = 8;

    struct nl_msg *nl_msg = ovpn_dco_v2_nlmsg_create(dco, OVPN_V2_CMD_NEW_KEY);
    if (!nl_msg)
    {
        return -ENOMEM;
    }

    dco_cipher_t dco_cipher = dco_get_cipher(ciphername);

    int ret = -EMSGSIZE;
    struct nlattr *attr = nla_nest_start(nl_msg, OVPN_V2_ATTR_NEW_KEY);
    NLA_PUT_U32(nl_msg, OVPN_V2_NEW_KEY_ATTR_PEER_ID, peerid);
    NLA_PUT_U8(nl_msg, OVPN_V2_NEW_KEY_ATTR_KEY_SLOT, slot);
    NLA_PUT_U8(nl_msg, OVPN_V2_NEW_KEY_ATTR_KEY_ID, keyid);
    NLA_PUT_U16(nl_msg, OVPN_V2_NEW_KEY_ATTR_CIPHER_ALG, dco_cipher);

    struct nlattr *key_enc = nla_nest_start(nl_msg,
                                            OVPN_V2_NEW_KEY_ATTR_ENCRYPT_KEY);
    if (dco_cipher != OVPN_CIPHER_ALG_NONE)
    {
        NLA_PUT(nl_msg, OVPN_V2_KEY_DIR_ATTR_CIPHER_KEY, key_len, encrypt_key);
        NLA_PUT(nl_msg, OVPN_V2_KEY_DIR_ATTR_NONCE_TAIL, nonce_tail_len,
                encrypt_iv);
    }
    nla_nest_end(nl_msg, key_enc);

    struct nlattr *key_dec = nla_nest_start(nl_msg,
                                            OVPN_V2_NEW_KEY_ATTR_DECRYPT_KEY);
    if (dco_cipher != OVPN_CIPHER_ALG_NONE)
    {
        NLA_PUT(nl_msg, OVPN_V2_KEY_DIR_ATTR_CIPHER_KEY, key_len, decrypt_key);
        NLA_PUT(nl_msg, OVPN_V2_KEY_DIR_ATTR_NONCE_TAIL, nonce_tail_len,
                decrypt_iv);
    }
    nla_nest_end(nl_msg, key_dec);

    nla_nest_end(nl_msg, attr);

    ret = ovpn_nl_msg_send(dco, nl_msg, NULL, NULL, __func__);

nla_put_failure:
    nlmsg_free(nl_msg);
    return ret;
}

int
dco_v2_set_peer(dco_context_t *dco, unsigned int peerid,
                int keepalive_interval, int keepalive_timeout, int mss)
{
    msg(D_DCO_DEBUG, "%s: peer-id %d, keepalive %d/%d, mss %d", __func__,
        peerid, keepalive_interval, keepalive_timeout, mss);

    struct nl_msg *nl_msg = ovpn_dco_v2_nlmsg_create(dco, OVPN_V2_CMD_SET_PEER);
    if (!nl_msg)
    {
        return -ENOMEM;
    }

    struct nlattr *attr = nla_nest_start(nl_msg, OVPN_V2_ATTR_SET_PEER);
    int ret = -EMSGSIZE;
    NLA_PUT_U32(nl_msg, OVPN_V2_SET_PEER_ATTR_PEER_ID, peerid);
    NLA_PUT_U32(nl_msg, OVPN_V2_SET_PEER_ATTR_KEEPALIVE_INTERVAL,
                keepalive_interval);
    NLA_PUT_U32(nl_msg, OVPN_V2_SET_PEER_ATTR_KEEPALIVE_TIMEOUT,
                keepalive_timeout);
    nla_nest_end(nl_msg, attr);

    ret = ovpn_nl_msg_send(dco, nl_msg, NULL, NULL, __func__);

nla_put_failure:
    nlmsg_free(nl_msg);
    return ret;
}

/* This function parses any netlink message sent by ovpn-dco to userspace */
static int
ovpn_v2_handle_msg(struct nl_msg *msg, void *arg)
{
    dco_context_t *dco = arg;

    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *attrs[OVPN_V2_ATTR_MAX + 1];
    struct nlmsghdr *nlh = nlmsg_hdr(msg);

    if (!genlmsg_valid_hdr(nlh, 0))
    {
        msg(D_DCO, "ovpn-dco: invalid header");
        return NL_SKIP;
    }

    if (nla_parse(attrs, OVPN_V2_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
                  genlmsg_attrlen(gnlh, 0), NULL))
    {
        msg(D_DCO, "received bogus data from ovpn-dco");
        return NL_SKIP;
    }

    /* we must know which interface this message is referring to in order to
     * avoid mixing messages for other instances
     */
    if (!attrs[OVPN_V2_ATTR_IFINDEX])
    {
        msg(D_DCO, "ovpn-dco: Received message without ifindex");
        return NL_SKIP;
    }

    uint32_t ifindex = nla_get_u32(attrs[OVPN_V2_ATTR_IFINDEX]);
    if (ifindex != dco->ifindex)
    {
        msg(D_DCO_DEBUG,
            "ovpn-dco: ignoring message (type=%d) for foreign ifindex %d",
            gnlh->cmd, ifindex);
        return NL_SKIP;
    }

    /* based on the message type, we parse the subobject contained in the
     * message, that stores the type-specific attributes.
     *
     * the "dco" object is then filled accordingly with the information
     * retrieved from the message, so that the rest of the OpenVPN code can
     * react as need be.
     */
    switch (gnlh->cmd)
    {
        case OVPN_V2_CMD_DEL_PEER:
        {
            if (!attrs[OVPN_V2_ATTR_DEL_PEER])
            {
                msg(D_DCO, "ovpn-dco: no attributes in OVPN_DEL_PEER message");
                return NL_SKIP;
            }

            struct nlattr *dp_attrs[OVPN_V2_DEL_PEER_ATTR_MAX + 1];
            if (nla_parse_nested(dp_attrs, OVPN_V2_DEL_PEER_ATTR_MAX,
                                 attrs[OVPN_V2_ATTR_DEL_PEER], NULL))
            {
                msg(D_DCO, "received bogus del peer packet data from ovpn-dco");
                return NL_SKIP;
            }

            if (!dp_attrs[OVPN_V2_DEL_PEER_ATTR_REASON])
            {
                msg(D_DCO, "ovpn-dco: no reason in DEL_PEER message");
                return NL_SKIP;
            }
            if (!dp_attrs[OVPN_V2_DEL_PEER_ATTR_PEER_ID])
            {
                msg(D_DCO, "ovpn-dco: no peer-id in DEL_PEER message");
                return NL_SKIP;
            }
            int reason = nla_get_u8(dp_attrs[OVPN_V2_DEL_PEER_ATTR_REASON]);
            unsigned int peerid = nla_get_u32(dp_attrs[OVPN_V2_DEL_PEER_ATTR_PEER_ID]);

            msg(D_DCO_DEBUG, "ovpn-dco: received CMD_DEL_PEER, ifindex: %d, peer-id %d, reason: %d",
                ifindex, peerid, reason);
            dco->dco_message_peer_id = peerid;
            dco->dco_del_peer_reason = reason;
            dco->dco_message_type = OVPN_V2_CMD_DEL_PEER;

            break;
        }

        default:
            msg(D_DCO, "ovpn-dco: received unknown command: %d", gnlh->cmd);
            dco->dco_message_type = 0;
            return NL_SKIP;
    }

    return NL_OK;
}

static int
dco_v2_do_read(dco_context_t *dco)
{
    msg(D_DCO_DEBUG, __func__);
    nl_cb_set(dco->nl_cb, NL_CB_VALID, NL_CB_CUSTOM, ovpn_v2_handle_msg, dco);

    return ovpn_nl_recvmsgs(dco, __func__);
}

static void
process_incoming_dco_v2(struct context *c)
{
    dco_context_t *dco = &c->c1.tuntap->dco;

    dco_v2_do_read(dco);

    switch (dco->dco_message_type)
    {
        case OVPN_V2_CMD_DEL_PEER:
            if (dco->dco_del_peer_reason == OVPN_DEL_PEER_REASON_EXPIRED)
            {
                msg(D_DCO_DEBUG, "%s: received peer expired notification of for peer-id "
                    "%d", __func__, dco->dco_message_peer_id);
                trigger_ping_timeout_signal(c);
                return;
            }
            break;

        case OVPN_V2_CMD_SWAP_KEYS:
            msg(D_DCO_DEBUG, "%s: received key rotation notification for peer-id %d",
                __func__, dco->dco_message_peer_id);
            tls_session_soft_reset(c->c2.tls_multi);
            break;

        default:
            msg(D_DCO_DEBUG, "%s: received message of type %u - ignoring", __func__,
                dco->dco_message_type);
            return;
    }
}

static void
dco_v2_update_peer_stat(struct context_2 *c2, struct nlattr *tb[], uint32_t id)
{
    if (tb[OVPN_V2_GET_PEER_RESP_ATTR_LINK_RX_BYTES])
    {
        c2->dco_read_bytes = nla_get_u64(tb[OVPN_V2_GET_PEER_RESP_ATTR_LINK_RX_BYTES]);
        msg(D_DCO_DEBUG, "%s / dco_read_bytes: " counter_format, __func__,
            c2->dco_read_bytes);
    }
    else
    {
        msg(M_WARN, "%s: no link RX bytes provided in reply for peer %u",
            __func__, id);
    }

    if (tb[OVPN_V2_GET_PEER_RESP_ATTR_LINK_TX_BYTES])
    {
        c2->dco_write_bytes = nla_get_u64(tb[OVPN_V2_GET_PEER_RESP_ATTR_LINK_TX_BYTES]);
        msg(D_DCO_DEBUG, "%s / dco_write_bytes: " counter_format, __func__,
            c2->dco_write_bytes);
    }
    else
    {
        msg(M_WARN, "%s: no link TX bytes provided in reply for peer %u",
            __func__, id);
    }

    if (tb[OVPN_V2_GET_PEER_RESP_ATTR_VPN_RX_BYTES])
    {
        c2->tun_read_bytes = nla_get_u64(tb[OVPN_V2_GET_PEER_RESP_ATTR_VPN_RX_BYTES]);
        msg(D_DCO_DEBUG, "%s / tun_read_bytes: " counter_format, __func__,
            c2->tun_read_bytes);
    }
    else
    {
        msg(M_WARN, "%s: no VPN RX bytes provided in reply for peer %u",
            __func__, id);
    }

    if (tb[OVPN_V2_GET_PEER_RESP_ATTR_VPN_TX_BYTES])
    {
        c2->tun_write_bytes = nla_get_u64(tb[OVPN_V2_GET_PEER_RESP_ATTR_VPN_TX_BYTES]);
        msg(D_DCO_DEBUG, "%s / tun_write_bytes: " counter_format, __func__,
            c2->tun_write_bytes);
    }
    else
    {
        msg(M_WARN, "%s: no VPN TX bytes provided in reply for peer %u",
            __func__, id);
    }
}

int
dco_v2_parse_peer_multi(struct nl_msg *msg, void *arg)
{
    struct nlattr *tb[OVPN_V2_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));

    msg(D_DCO_DEBUG, "%s: parsing message...", __func__);

    nla_parse(tb, OVPN_V2_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
              genlmsg_attrlen(gnlh, 0), NULL);

    if (!tb[OVPN_V2_ATTR_GET_PEER])
    {
        return NL_SKIP;
    }

    struct nlattr *tb_peer[OVPN_V2_GET_PEER_RESP_ATTR_MAX + 1];

    nla_parse(tb_peer, OVPN_V2_GET_PEER_RESP_ATTR_MAX,
              nla_data(tb[OVPN_V2_ATTR_GET_PEER]),
              nla_len(tb[OVPN_V2_ATTR_GET_PEER]), NULL);

    if (!tb_peer[OVPN_V2_GET_PEER_RESP_ATTR_PEER_ID])
    {
        msg(M_WARN, "%s: no peer-id provided in reply", __func__);
        return NL_SKIP;
    }

    struct multi_context *m = arg;
    uint32_t peer_id = nla_get_u32(tb_peer[OVPN_V2_GET_PEER_RESP_ATTR_PEER_ID]);

    if (peer_id >= m->max_clients || !m->instances[peer_id])
    {
        msg(M_WARN, "%s: cannot store DCO stats for peer %u", __func__,
            peer_id);
        return NL_SKIP;
    }

    dco_v2_update_peer_stat(&m->instances[peer_id]->context.c2, tb_peer, peer_id);

    return NL_OK;
}

int
dco_v2_get_peer_stats_multi(dco_context_t *dco, struct multi_context *m)
{
    msg(D_DCO_DEBUG, "%s", __func__);

    struct nl_msg *nl_msg = ovpn_dco_v2_nlmsg_create(dco, OVPN_V2_CMD_GET_PEER);

    nlmsg_hdr(nl_msg)->nlmsg_flags |= NLM_F_DUMP;

    int ret = ovpn_nl_msg_send(dco, nl_msg, dco_v2_parse_peer_multi, m, __func__);

    nlmsg_free(nl_msg);
    return ret;
}

static int
dco_v2_parse_peer(struct nl_msg *msg, void *arg)
{
    struct context *c = arg;
    struct nlattr *tb[OVPN_V2_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));

    msg(D_DCO_DEBUG, "%s: parsing message...", __func__);

    nla_parse(tb, OVPN_V2_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
              genlmsg_attrlen(gnlh, 0), NULL);

    if (!tb[OVPN_V2_ATTR_GET_PEER])
    {
        msg(D_DCO_DEBUG, "%s: malformed reply", __func__);
        return NL_SKIP;
    }

    struct nlattr *tb_peer[OVPN_V2_GET_PEER_RESP_ATTR_MAX + 1];

    nla_parse(tb_peer, OVPN_V2_GET_PEER_RESP_ATTR_MAX,
              nla_data(tb[OVPN_V2_ATTR_GET_PEER]),
              nla_len(tb[OVPN_V2_ATTR_GET_PEER]), NULL);

    if (!tb_peer[OVPN_V2_GET_PEER_RESP_ATTR_PEER_ID])
    {
        msg(M_WARN, "%s: no peer-id provided in reply", __func__);
        return NL_SKIP;
    }

    uint32_t peer_id = nla_get_u32(tb_peer[OVPN_V2_GET_PEER_RESP_ATTR_PEER_ID]);
    if (c->c2.tls_multi->dco_peer_id != peer_id)
    {
        return NL_SKIP;
    }

    dco_v2_update_peer_stat(&c->c2, tb_peer, peer_id);

    return NL_OK;
}

int
dco_v2_get_peer_stats(struct context *c)
{
    uint32_t peer_id = c->c2.tls_multi->dco_peer_id;
    msg(D_DCO_DEBUG, "%s: peer-id %d", __func__, peer_id);

    if (!c->c1.tuntap)
    {
        return 0;
    }

    dco_context_t *dco = &c->c1.tuntap->dco;
    struct nl_msg *nl_msg = ovpn_dco_v2_nlmsg_create(dco, OVPN_V2_CMD_GET_PEER);
    struct nlattr *attr = nla_nest_start(nl_msg, OVPN_V2_ATTR_GET_PEER);
    int ret = -EMSGSIZE;

    NLA_PUT_U32(nl_msg, OVPN_V2_GET_PEER_ATTR_PEER_ID, peer_id);
    nla_nest_end(nl_msg, attr);

    ret = ovpn_nl_msg_send(dco, nl_msg, dco_v2_parse_peer, c, __func__);

nla_put_failure:
    nlmsg_free(nl_msg);
    return ret;
}

const struct dco_ops dco_ops_v2 = {
    .ovpn_dco_nlmsg_create = ovpn_dco_v2_nlmsg_create,
    .dco_new_peer = &dco_v2_new_peer,
    .open_tun_dco = open_tun_dco_v2,
    .close_tun_dco = close_tun_dco_v2,
    .dco_swap_keys = &dco_v2_swap_keys,
    .dco_del_peer = &dco_v2_del_peer,
    .dco_del_key = &dco_v2_del_key,
    .dco_new_key = &dco_v2_new_key,
    .dco_set_peer = &dco_v2_set_peer,
    .ovpn_handle_msg = &ovpn_v2_handle_msg,
    .process_incoming_dco = &process_incoming_dco_v2,
    .dco_do_read = &dco_v2_do_read,
    .dco_update_peer_stat = &dco_v2_update_peer_stat,
    .dco_parse_peer_multi = &dco_v2_parse_peer_multi,
    .dco_get_peer_stats_multi = &dco_v2_get_peer_stats_multi,
    .dco_parse_peer = &dco_v2_parse_peer,
    .dco_get_peer_stats = &dco_v2_get_peer_stats
};

#endif /* defined(ENABLE_DCO) && defined(TARGET_LINUX) */
