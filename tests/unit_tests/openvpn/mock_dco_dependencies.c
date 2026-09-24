/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2026 OpenVPN Inc <sales@openvpn.net>
 *  Copyright (C) 2026 Gianmarco De Gregori <gianmarco@mandelbit.com>
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
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, see <https://www.gnu.org/licenses/>.
 */

/*
 *  Stubs for what dco_linux.c drags in but capability probing never reaches:
 *  the data path, the event loop and the signal machinery.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"
#include "dco.h"

void
multi_process_incoming_dco(dco_context_t *dco)
{
}

void
process_incoming_dco(dco_context_t *dco)
{
}

void
register_signal(struct signal_info *si, int signum, const char *signal_text)
{
}

int
net_iface_new(openvpn_net_ctx_t *ctx, const char *iface, const char *type, void *arg)
{
    return 0;
}

int
net_iface_del(openvpn_net_ctx_t *ctx, const char *iface)
{
    return 0;
}

int
cipher_kt_key_size(const char *ciphername)
{
    return 0;
}

const char *
print_sockaddr_ex(const struct sockaddr *addr, const char *separator, const unsigned int flags,
                  struct gc_arena *gc)
{
    return "[mock]";
}
