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

typedef char openvpn_net_iface_t;
typedef void *openvpn_net_ctx_t;

#if defined(TARGET_LINUX)

#include <linux/if_link.h>

#ifndef IFLA_OVPN_MAX

enum ovpn_mode
{
    OVPN_MODE_P2P,
    OVPN_MODE_MP,
};

enum ovpn_ifla_attrs
{
    IFLA_OVPN_UNSPEC = 0,
    IFLA_OVPN_MODE,

    __IFLA_OVPN_MAX,
};

#define IFLA_OVPN_MAX (__IFLA_OVPN_MAX - 1)

#endif /* ifndef IFLA_OVPN_MAX */

#endif /* if defined(TARGET_LINUX) */

#endif /* NETWORKING_SITNL_H_ */
