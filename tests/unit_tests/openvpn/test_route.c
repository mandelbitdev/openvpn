/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2026 OpenVPN Inc <sales@openvpn.net>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"

#include "test_common.h"

#include "route.h"
#include "networking.h"

#include "test_route.h"

/* Stubs for functions route.c references but that no test here reaches.
 * They assert rather than return quietly, so a test straying onto one
 * fails loudly instead of silently doing nothing.
 */
struct argv
argv_new(void)
{
    assert_true(0);
    struct argv a = { 0 };
    return a;
}

void
argv_free(struct argv *a)
{
    assert_true(0);
}

bool
get_ipv6_addr(const char *prefix_str, struct in6_addr *network, unsigned int *netbits,
              msglvl_t msglevel)
{
    assert_true(0);
    return false;
}

in_addr_t
getaddr(unsigned int flags, const char *hostname, int resolve_retry, bool *succeeded,
        struct signal_info *sig_info)
{
    assert_true(0);
    return 0;
}

int
openvpn_getaddrinfo(unsigned int flags, const char *hostname, const char *servname,
                    int resolve_retry_seconds, struct signal_info *sig_info, int ai_family,
                    struct addrinfo **res)
{
    assert_true(0);
    return 0;
}

struct signal_info siginfo_static; /* GLOBAL */

int
signal_reset(struct signal_info *si, int signum)
{
    assert_true(0);
    return 0;
}

static void
test_is_special_addr(void **state)
{
    assert_true(is_special_addr("net_gateway"));
    assert_true(is_special_addr("vpn_gateway"));
    assert_true(is_special_addr("remote_host"));

    assert_false(is_special_addr("10.0.0.1"));
    assert_false(is_special_addr("default"));
    assert_false(is_special_addr(NULL));
}

static void
test_netmask_to_netbits(void **state)
{
    int netbits;

    assert_true(netmask_to_netbits(0x0a000000, 0xff000000, &netbits)); /* 10/8 */
    assert_int_equal(netbits, 8);

    assert_true(netmask_to_netbits(0xc0a80100, 0xffffff00, &netbits)); /* 192.168.1/24 */
    assert_int_equal(netbits, 24);

    assert_true(netmask_to_netbits(0x00000000, 0x00000000, &netbits)); /* default route */
    assert_int_equal(netbits, 0);

    /* a full-length mask reports -1 rather than 32 */
    assert_true(netmask_to_netbits(0x0a010203, 0xffffffff, &netbits));
    assert_int_equal(netbits, -1);

    /* host bits set in the network part */
    assert_false(netmask_to_netbits(0x0a000001, 0xff000000, &netbits));

    /* not a contiguous netmask */
    assert_false(netmask_to_netbits(0x0a000000, 0xff00ff00, &netbits));
}

static void
test_netmask_to_netbits2(void **state)
{
    assert_int_equal(netmask_to_netbits2(0xff000000), 8);
    assert_int_equal(netmask_to_netbits2(0xffffff00), 24);
    assert_int_equal(netmask_to_netbits2(0x00000000), 0);

    /* unlike netmask_to_netbits(), this one reports a full-length mask as 32 */
    assert_int_equal(netmask_to_netbits2(0xffffffff), 32);

    assert_int_equal(netmask_to_netbits2(0xff00ff00), -1);
}

static void
assert_clear_host_bits(const char *addr, unsigned int netbits, const char *expected)
{
    struct route_ipv6 r6;
    struct in6_addr want;

    CLEAR(r6);
    assert_int_equal(inet_pton(AF_INET6, addr, &r6.network), 1);
    assert_int_equal(inet_pton(AF_INET6, expected, &want), 1);
    r6.netbits = netbits;

    route_ipv6_clear_host_bits(&r6);
    assert_memory_equal(&r6.network, &want, sizeof(struct in6_addr));
}

static void
test_route_ipv6_clear_host_bits(void **state)
{
    /* whole bytes cleared */
    assert_clear_host_bits("2001:db8::1", 64, "2001:db8::");
    assert_clear_host_bits("2001:db8:dead:beef::1", 32, "2001:db8::");

    /* a prefix that does not fall on a byte boundary */
    assert_clear_host_bits("2001:db8:0:00ff::1", 60, "2001:db8:0:00f0::");
    assert_clear_host_bits("2001:db8::ffff", 121, "2001:db8::ff80");

    /* nothing to clear, and everything to clear */
    assert_clear_host_bits("2001:db8::1", 128, "2001:db8::1");
    assert_clear_host_bits("2001:db8::1", 0, "::");
}

#if defined(TARGET_LINUX) && !defined(TARGET_ANDROID)
static in_addr_t
ip4(const char *s)
{
    in_addr_t a;
    assert_int_equal(inet_pton(AF_INET, s, &a), 1);
    return ntohl(a);
}

static void
test_route_list_add_extra_remote(void **state)
{
    struct route_list rl;
    CLEAR(rl);
    rl.flags = RG_ENABLE;
    rl.spec.flags = RTSA_REMOTE_HOST;
    rl.spec.remote_host = ip4("192.0.2.1");
    rl.rgi.flags = RGI_ADDR_DEFINED | RGI_NETMASK_DEFINED | RGI_IFACE_DEFINED;
    rl.rgi.gateway.addr = ip4("10.0.1.1");
    rl.rgi.gateway.netmask = ip4("255.255.255.0");

    /* the remote host and on-link addresses are skipped */
    route_list_add_extra_remote(&rl, ip4("192.0.2.1"));
    route_list_add_extra_remote(&rl, ip4("10.0.1.7"));
    assert_int_equal(rl.spec.bypass.n_bypass, 0);

    /* added once */
    route_list_add_extra_remote(&rl, ip4("198.51.100.1"));
    route_list_add_extra_remote(&rl, ip4("198.51.100.1"));
    assert_int_equal(rl.spec.bypass.n_bypass, 1);
    assert_int_equal(rl.spec.bypass.bypass[0], ip4("198.51.100.1"));

    /* full bypass list */
    for (in_addr_t a = ip4("198.51.100.2"); rl.spec.bypass.n_bypass < N_ROUTE_BYPASS; a++)
    {
        route_list_add_extra_remote(&rl, a);
    }
    route_list_add_extra_remote(&rl, ip4("198.51.100.100"));
    assert_int_equal(rl.spec.bypass.n_bypass, N_ROUTE_BYPASS);
    assert_int_not_equal(rl.spec.bypass.bypass[N_ROUTE_BYPASS - 1], ip4("198.51.100.100"));

    /* nothing without --redirect-gateway */
    CLEAR(rl.spec.bypass);
    rl.flags = 0;
    route_list_add_extra_remote(&rl, ip4("198.51.100.1"));
    assert_int_equal(rl.spec.bypass.n_bypass, 0);
}

static void
add_test_route_ipv6(struct route_ipv6_list *rl6, const char *network, unsigned int netbits)
{
    struct route_ipv6 *r6;
    ALLOC_OBJ_CLEAR_GC(r6, struct route_ipv6, &rl6->gc);
    assert_int_equal(inet_pton(AF_INET6, network, &r6->network), 1);
    r6->netbits = netbits;
    r6->next = rl6->routes_ipv6;
    rl6->routes_ipv6 = r6;
}

static int
count_routes_ipv6(const struct route_ipv6_list *rl6)
{
    int n = 0;
    for (const struct route_ipv6 *r6 = rl6->routes_ipv6; r6; r6 = r6->next)
    {
        n++;
    }
    return n;
}

static void
test_route_ipv6_list_add_extra_remote(void **state)
{
    struct route_ipv6_list rl6;
    struct in6_addr host, gateway;

    CLEAR(rl6);
    rl6.gc = gc_new();
    rl6.spec_flags = RTSA_REMOTE_HOST;
    assert_int_equal(inet_pton(AF_INET6, "2001:db8:1::1", &rl6.remote_host_ipv6), 1);
    rl6.rgi6.flags = RGI_ADDR_DEFINED | RGI_IFACE_DEFINED;
    assert_int_equal(inet_pton(AF_INET6, "fd00:1::1", &gateway), 1);
    rl6.rgi6.gateway.addr_ipv6 = gateway;
    strlcpy(rl6.rgi6.iface, "eth0", sizeof(rl6.rgi6.iface));
    add_test_route_ipv6(&rl6, "2000::", 3);

    /* the remote host is skipped */
    route_ipv6_list_add_extra_remote(&rl6, &rl6.remote_host_ipv6);
    assert_int_equal(count_routes_ipv6(&rl6), 1);

    /* not routed into the tunnel */
    assert_int_equal(inet_pton(AF_INET6, "fd00:2::1", &host), 1);
    route_ipv6_list_add_extra_remote(&rl6, &host);
    assert_int_equal(count_routes_ipv6(&rl6), 1);

    /* added once, as a host route via the original gateway */
    assert_int_equal(inet_pton(AF_INET6, "2001:db8:2::1", &host), 1);
    route_ipv6_list_add_extra_remote(&rl6, &host);
    route_ipv6_list_add_extra_remote(&rl6, &host);
    assert_int_equal(count_routes_ipv6(&rl6), 2);

    const struct route_ipv6 *r6 = rl6.routes_ipv6;
    assert_memory_equal(&r6->network, &host, sizeof(host));
    assert_int_equal(r6->netbits, 128);
    assert_memory_equal(&r6->gateway, &gateway, sizeof(gateway));
    assert_string_equal(r6->iface, "eth0");
    assert_int_equal(r6->flags, RT_DEFINED | RT_METRIC_DEFINED);

    /* nothing without the original gateway */
    rl6.rgi6.flags = 0;
    assert_int_equal(inet_pton(AF_INET6, "2001:db8:3::1", &host), 1);
    route_ipv6_list_add_extra_remote(&rl6, &host);
    assert_int_equal(count_routes_ipv6(&rl6), 2);

    gc_free(&rl6.gc);
}
#endif

static const struct CMUnitTest route_test_list[] = {
    cmocka_unit_test(test_is_special_addr),
    cmocka_unit_test(test_netmask_to_netbits),
    cmocka_unit_test(test_netmask_to_netbits2),
    cmocka_unit_test(test_route_ipv6_clear_host_bits),
#if defined(TARGET_LINUX) && !defined(TARGET_ANDROID)
    cmocka_unit_test(test_route_list_add_extra_remote),
    cmocka_unit_test(test_route_ipv6_list_add_extra_remote),
#endif
};

int
route_tests(void)
{
    openvpn_unit_test_setup();
    return cmocka_run_group_tests(route_test_list, NULL, NULL);
}
