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
    struct gc_arena gc;
};

typedef struct openvpn_net_ctx openvpn_net_ctx_t;

/**
 * @brief Switch the current thread to the specified network namespace.
 *
 * This function changes the calling thread's network namespace to the one
 * identified by @p name. The current (original) network namespace file
 * descriptor is saved and returned, so it can later be restored using
 * netns_restore().
 *
 * The switch is performed using setns(2). This approach is required because
 * the netlink library does not support performing operations in an arbitrary
 * target network namespace, except for interface creation and deletion.
 * Therefore, in order to execute generic netlink operations inside a
 * specific network namespace, the thread must temporarily enter
 * that namespace via setns().
 *
 * @param name  Name of the target network namespace (as found under
 *              NETNS_RUN_DIR, e.g. /var/run/netns/<name>).
 *
 * @return On success, returns a file descriptor referring to the original
 *         network namespace. This descriptor must be passed to
 *         netns_restore() to switch back.
 * @return -1 on failure (an error is logged and no namespace switch is kept).
 *
 * @note The returned file descriptor must be closed by calling
 *       netns_restore(). Failing to do so may leak file descriptors.
 */
int netns_switch(const char *name);

/**
 * @brief Restore the previously saved network namespace.
 *
 * This function restores the network namespace saved by netns_switch()
 * using the file descriptor returned by that function.
 *
 * The restoration is performed using setns(2), switching the calling
 * thread back to its original network namespace.
 *
 * @param orig_fd  File descriptor of the original network namespace,
 *                 as returned by netns_switch().
 *
 * @return 0 on success.
 * @return -1 on failure (an error is logged and the file descriptor
 *         is closed).
 *
 * @note This function closes @p orig_fd in all cases.
 *       After calling this function, @p orig_fd must not be reused.
 */
int netns_restore(int orig_fd);

/**
 * Resolve a network interface name to its interface index.
 *
 * If a valid network namespace ID is provided, the lookup is performed inside
 * that network namespace using Netlink. Otherwise, this function falls back
 * to the standard `if_nametoindex()` call in the current namespace.
 *
 * @param ifname   Name of the network interface.
 * @param netnsid  Network namespace ID, or a negative value to use the current
 *                 namespace.
 *
 * @return Interface index on success, or 0 on error.
 */
int openvpn_if_nametoindex(const char *ifname, int netnsid);

/**
 * Move a network interface to a different network namespace.
 *
 * This function moves the specified network interface from the current
 * network namespace into the target network namespace identified by name.
 * The operation is performed via a RTM_SETLINK Netlink request using the
 * IFLA_NET_NS_FD attribute.
 *
 * The target network namespace is expected to exist under NETNS_RUN_DIR
 * (/var/run/netns).
 *
 * @param iface  Name of the network interface to move.
 * @param netns  Name of the target network namespace.
 *
 * @return 0 on success, or a negative error code on failure.
 */
int net_iface_move_netns(const char *iface, const char *netns);

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
