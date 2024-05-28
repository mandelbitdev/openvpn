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
#ifndef DCO_LINUX_H
#define DCO_LINUX_H

#if defined(ENABLE_DCO) && defined(TARGET_LINUX)

#include "event.h"

#include "ovpn_dco_linux.h"
#include "ovpn_dco_v3.h"

#include <netlink/socket.h>
#include <netlink/netlink.h>

#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>

#include "networking.h"
#include "fdmisc.h"

/* forward declarations (including other headers leads to nasty include
 * order problems)
 */
struct multi_context;
struct context_2;
struct key_ctx_bi;

typedef enum ovpn_key_slot dco_key_slot_t;
typedef enum ovpn_cipher_alg dco_cipher_t;

/* libnl < 3.5.0 does not set the NLA_F_NESTED on its own, therefore we
 * have to explicitly do it to prevent the kernel from failing upon
 * parsing of the message
 */
#define nla_nest_start(_msg, _type) \
    nla_nest_start(_msg, (_type) | NLA_F_NESTED)


typedef struct
{
    struct nl_sock *nl_sock;
    struct nl_cb *nl_cb;
    int status;

    enum ovpn_v2_mode ifmode;

    int ovpn_dco_id;
    int ovpn_dco_mcast_id;

    unsigned int ifindex;

    int dco_message_type;
    int dco_message_peer_id;
    int dco_del_peer_reason;
    uint64_t dco_read_bytes;
    uint64_t dco_write_bytes;

    const struct dco_ops *ops;
} dco_context_t;

struct dco_ops
{
    struct nl_msg *(*ovpn_dco_nlmsg_create)(dco_context_t *dco, int cmd);
    int (*dco_new_peer)(dco_context_t *dco, unsigned int peerid, int sd, struct sockaddr *localaddr, struct sockaddr *remoteaddr, struct in_addr *remote_in4, struct in6_addr *remote_in6);
    int (*open_tun_dco)(struct tuntap *tt, openvpn_net_ctx_t *ctx, const char *dev);
    void (*close_tun_dco)(struct tuntap *tt, openvpn_net_ctx_t *ctx);
    int (*dco_swap_keys)(dco_context_t *dco, unsigned int peerid);
    int (*dco_del_peer)(dco_context_t *dco, unsigned int peerid);
    int (*dco_del_key)(dco_context_t *dco, unsigned int peerid, dco_key_slot_t slot);
    int (*dco_new_key)(dco_context_t *dco, unsigned int peerid, int keyid, dco_key_slot_t slot, const uint8_t *encrypt_key, const uint8_t *encrypt_iv, const uint8_t *decrypt_key, const uint8_t *decrypt_iv, const char *ciphername);
    int (*dco_set_peer)(dco_context_t *dco, unsigned int peerid, int keepalive_interval, int keepalive_timeout, int mss);
    int (*ovpn_handle_msg)(struct nl_msg *msg, void *arg);
    int (*dco_do_read)(dco_context_t *dco);
    void (*dco_update_peer_stat)(struct context_2 *c2, struct nlattr *tb[], uint32_t id);
    int (*dco_parse_peer_multi)(struct nl_msg *msg, void *arg);
    int (*dco_get_peer_stats_multi)(dco_context_t *dco, struct multi_context *m);
    int (*dco_parse_peer)(struct nl_msg *msg, void *arg);
    int (*dco_get_peer_stats)(struct context *c);
};

extern const struct dco_ops dco_ops_v2;
extern const struct dco_ops dco_ops_v3;

int ovpn_get_mcast_id(dco_context_t *dco);

void dco_check_key_ctx(const struct key_ctx_bi *key);

typedef int (*ovpn_nl_cb)(struct nl_msg *msg, void *arg);

/**
 * @brief resolves the netlink ID for ovpn-dco
 *
 * This function queries the kernel via a netlink socket
 * whether the ovpn-dco netlink namespace is available
 *
 * This function can be used to determine if the kernel
 * supports DCO offloading.
 *
 * @return ID on success, negative error code on error
 */
int resolve_ovpn_netlink_id(int msglevel, dco_context_t *dco);

int ovpn_nl_recvmsgs(dco_context_t *dco, const char *prefix);

/**
 * Send a prepared netlink message and registers cb as callback if non-null.
 *
 * The method will also free nl_msg
 * @param dco       The dco context to use
 * @param nl_msg    the message to use
 * @param cb        An optional callback if the caller expects an answer
 * @param cb_arg    An optional param to pass to the callback
 * @param prefix    A prefix to report in the error message to give the user context
 * @return          status of sending the message
 */
int ovpn_nl_msg_send(dco_context_t *dco, struct nl_msg *nl_msg, ovpn_nl_cb cb,
                     void *cb_arg, const char *prefix);

struct sockaddr *
mapped_v4_to_v6(struct sockaddr *sock, struct gc_arena *gc);

int ovpn_nl_cb_finish(struct nl_msg (*msg) __attribute__ ((unused)), void *arg);

/* This function is used as error callback on the netlink socket.
 * When something goes wrong and the kernel returns an error, this function is
 * invoked.
 *
 * We pass the error code to the user by means of a variable pointed by *arg
 * (supplied by the user when setting this callback) and we parse the kernel
 * reply to see if it contains a human-readable error. If found, it is printed.
 */
int ovpn_nl_cb_error(struct sockaddr_nl (*nla) __attribute__ ((unused)),
                     struct nlmsgerr *err, void *arg);

void ovpn_dco_init_netlink(dco_context_t *dco);

bool ovpn_dco_init(int mode, dco_context_t *dco);

void ovpn_dco_uninit_netlink(dco_context_t *dco);

void ovpn_dco_register(dco_context_t *dco);

/* This function parses the reply provided by the kernel to the CTRL_CMD_GETFAMILY
 * message. We parse the reply and we retrieve the multicast group ID associated
 * with the "ovpn-dco" netlink family.
 *
 * The ID is later used to subscribe to the multicast group and be notified
 * about any multicast message sent by the ovpn-dco kernel module.
 */
int mcast_family_handler(struct nl_msg *msg, void *arg);

/**
 * Lookup the multicast id for OpenVPN. This method and its help method currently
 * hardcode the lookup to OVPN_NL_NAME and OVPN_NL_MULTICAST_GROUP_PEERS but
 * extended in the future if we need to lookup more than one mcast id.
 */
int ovpn_get_mcast_id(dco_context_t *dco);

bool dco_available(int msglevel, dco_context_t *dco);

const char *dco_version_string(struct gc_arena *gc);

void dco_event_set(dco_context_t *dco, struct event_set *es, void *arg);

const char *dco_get_supported_ciphers();

#endif /* defined(ENABLE_DCO) && defined(TARGET_LINUX) */
#endif /* ifndef DCO_LINUX_H */
