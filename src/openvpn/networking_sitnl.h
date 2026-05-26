/*
 *  Generic interface to platform specific networking code
 *
 *  Copyright (C) 2016-2026 Antonio Quartulli <a@unstable.cc>
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
 *  distribution); if not, see <https://www.gnu.org/licenses/>.
 */


#ifndef NETWORKING_SITNL_H_
#define NETWORKING_SITNL_H_

#include "env_set.h"

typedef char openvpn_net_iface_t;

struct openvpn_net_ctx
{
    const char *netns;
    const char *l3mdev;
    struct gc_arena gc;
};

typedef struct openvpn_net_ctx openvpn_net_ctx_t;

/**
 * @brief Switch the current thread to the network namespace specified
 *        in the given OpenVPN network context.
 *
 * This function changes the calling thread's network namespace to the one
 * identified by ctx->netns. The current (original) network namespace file
 * descriptor is saved and returned, so it can later be restored using
 * netns_restore().
 *
 * If @p ctx is NULL or ctx->netns is NULL, the function fails and returns -1.
 *
 * The switch is performed using setns(2). This approach is required because
 * the netlink library does not support performing operations in an arbitrary
 * target network namespace, except for interface creation and deletion.
 * Therefore, in order to execute generic netlink operations inside a
 * specific network namespace, the thread must temporarily enter
 * that namespace via setns().
 *
 * @param ctx  Pointer to an OpenVPN network context structure containing
 *             the target network namespace name (ctx->netns). The namespace
 *             is expected to exist under NETNS_RUN_DIR (e.g. /run/netns/).
 *
 * @return On success, returns a file descriptor referring to the original
 *         network namespace. This descriptor must be passed to
 *         netns_restore() to switch back.
 * @return -1 on failure (an error is logged and no namespace switch is kept).
 *
 * @note The returned file descriptor must be passed to netns_restore(),
 *       which will restore the original namespace and close it.
 */
int netns_switch(openvpn_net_ctx_t *ctx);

/**
 * @brief Restore the previously saved network namespace.
 *
 * This function restores the network namespace saved by netns_switch()
 * using the file descriptor returned by that function.
 *
 * If @p orig_fd is negative, the function does nothing and returns
 * immediately.
 *
 * The restoration is performed using setns(2), switching the calling
 * thread back to its original network namespace.
 *
 * @param orig_fd  File descriptor of the original network namespace,
 *                 as returned by netns_switch().
 *
 * @note This function always closes @p orig_fd if it is >= 0,
 *       regardless of whether setns() succeeds or fails.
 *       After calling this function, @p orig_fd must not be reused.
 */
void netns_restore(int orig_fd);

/**
 * Resolve a network interface name to its interface index.
 *
 * If a valid network namespace ID is provided, the lookup is performed inside
 * that network namespace using Netlink. Otherwise, this function falls back
 * to the standard `if_nametoindex()` call in the current namespace.
 *
 * @param ifname   Name of the network interface.
 * @param ctx      The network context where we retrieve
 *                 the network namespace name.
 *
 * @return Interface index on success, or 0 on error.
 */
int openvpn_if_nametoindex(const char *ifname, openvpn_net_ctx_t *ctx);

/**
 * Retrieve or create a network namespace ID (NSID) for a given namespace.
 *
 * This function first attempts to retrieve the NSID associated with the
 * specified network namespace. If no NSID is currently assigned, it
 * requests the kernel to create one and then retries the lookup.
 *
 * @param name  Name of the network namespace.
 *
 * @return The network namespace ID on success, or -1 on failure.
 */
int get_or_create_netnsid_sitnl(const char *name);

#endif /* NETWORKING_SITNL_H_ */
