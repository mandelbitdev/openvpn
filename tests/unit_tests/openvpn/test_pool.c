/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2026 OpenVPN Inc <sales@openvpn.net>
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

#include <stdlib.h>
#include <setjmp.h>
#include <cmocka.h>

#include "pool.h"
#include "buffer.h"
#include "platform.h"
#include "test_common.h"
#include "mock_msg.h"

/*
 * pool.c pulls in a few socket.c/socket_util.c helpers for address parsing and
 * formatting.  The pool logic under test does not need the full socket stack,
 * so provide small IPv4 implementations here (the IPv6 ones are not reached by
 * these IPv4-only pools, but must exist to link).
 */
struct signal_info;

in_addr_t
getaddr(unsigned int flags, const char *hostname, int resolve_retry_seconds, bool *succeeded,
        struct signal_info *sig_info)
{
    struct in_addr a;
    int ok = inet_pton(AF_INET, hostname, &a) == 1;

    if (succeeded)
    {
        *succeeded = ok;
    }
    return ok ? ntohl(a.s_addr) : 0;
}

const char *
print_in_addr_t(in_addr_t addr, unsigned int flags, struct gc_arena *gc)
{
    struct in_addr a = { .s_addr = htonl(addr) };
    char buf[INET_ADDRSTRLEN] = { 0 };

    inet_ntop(AF_INET, &a, buf, sizeof(buf));
    return string_alloc(buf, gc);
}

bool
get_ipv6_addr(const char *hostname, struct in6_addr *network, unsigned int *netbits,
              msglvl_t msglevel)
{
    return false;
}

const char *
print_in6_addr(struct in6_addr a6, unsigned int flags, struct gc_arena *gc)
{
    return "";
}

struct in6_addr
add_in6_addr(struct in6_addr base, uint32_t add)
{
    return base;
}

#define IP(a, b, c, d) (((in_addr_t)(a) << 24) | ((b) << 16) | ((c) << 8) | (d))

/* three non-overlapping /24 pools: the global one and two --subnet-pool groups */
#define GLOBAL_START IP(10, 1, 1, 2)
#define GLOBAL_END   IP(10, 1, 1, 254)
#define A_START      IP(10, 2, 1, 2)
#define A_END        IP(10, 2, 1, 254)
#define B_START      IP(10, 2, 2, 2)
#define B_END        IP(10, 2, 2, 254)

static struct ifconfig_pool *
make_pool(in_addr_t start, in_addr_t end)
{
    struct in6_addr any = { 0 };

    return ifconfig_pool_init(true, IFCONFIG_POOL_INDIV, start, end, false, false, any, 0);
}

static in_addr_t
acquire(struct ifconfig_pool *pool, const char *cn)
{
    in_addr_t local = 0, remote = 0;

    ifconfig_pool_acquire(pool, &local, &remote, NULL, cn);
    return remote;
}

/* whether any entry of the pool is reserved for common name cn */
static bool
pool_has_cn(const struct ifconfig_pool *pool, const char *cn)
{
    for (int i = 0; i < pool->size; ++i)
    {
        if (pool->list[i].common_name && !strcmp(pool->list[i].common_name, cn))
        {
            return true;
        }
    }
    return false;
}

static const char *persist_file;

/* Write {global, A, B} to one persist file, reload into a fresh set, and check
 * that every entry was routed back to the pool that owns its address. */
static void
test_persist_roundtrip(void **state)
{
    struct ifconfig_pool *g = make_pool(GLOBAL_START, GLOBAL_END);
    struct ifconfig_pool *a = make_pool(A_START, A_END);
    struct ifconfig_pool *b = make_pool(B_START, B_END);

    assert_int_equal(acquire(g, "alice"), GLOBAL_START);
    assert_int_equal(acquire(a, "bob"), A_START);
    assert_int_equal(acquire(b, "carol"), B_START);

    struct ifconfig_pool *pools[] = { g, a, b };
    struct ifconfig_pool_persist *wp = ifconfig_pool_persist_init(persist_file, 5);
    ifconfig_pool_write(wp, pools, 3);
    ifconfig_pool_persist_close(wp);

    struct ifconfig_pool *g2 = make_pool(GLOBAL_START, GLOBAL_END);
    struct ifconfig_pool *a2 = make_pool(A_START, A_END);
    struct ifconfig_pool *b2 = make_pool(B_START, B_END);
    struct ifconfig_pool *pools2[] = { g2, a2, b2 };
    struct ifconfig_pool_persist *rp = ifconfig_pool_persist_init(persist_file, 0);
    ifconfig_pool_read(rp, pools2, 3);
    ifconfig_pool_persist_close(rp);

    /* each client was routed to its own pool (handle 0 == the pool's base) */
    assert_string_equal(g2->list[0].common_name, "alice");
    assert_string_equal(a2->list[0].common_name, "bob");
    assert_string_equal(b2->list[0].common_name, "carol");

    /* and nowhere else */
    assert_false(pool_has_cn(g2, "bob"));
    assert_false(pool_has_cn(g2, "carol"));
    assert_false(pool_has_cn(a2, "alice"));

    /* the reservation is honoured: the same CN gets its persisted address back */
    assert_int_equal(acquire(a2, "bob"), A_START);

    ifconfig_pool_free(g);
    ifconfig_pool_free(a);
    ifconfig_pool_free(b);
    ifconfig_pool_free(g2);
    ifconfig_pool_free(a2);
    ifconfig_pool_free(b2);
}

/* An entry whose address matches no configured pool (here: B's, when B is not
 * in the set) is ignored on load and does not disturb the other pools. */
static void
test_persist_ignore_unknown(void **state)
{
    struct ifconfig_pool *g = make_pool(GLOBAL_START, GLOBAL_END);
    struct ifconfig_pool *a = make_pool(A_START, A_END);
    struct ifconfig_pool *b = make_pool(B_START, B_END);

    acquire(g, "alice");
    acquire(a, "bob");
    acquire(b, "carol");

    struct ifconfig_pool *pools[] = { g, a, b };
    struct ifconfig_pool_persist *wp = ifconfig_pool_persist_init(persist_file, 5);
    ifconfig_pool_write(wp, pools, 3);
    ifconfig_pool_persist_close(wp);

    /* reload into a set WITHOUT pool B: carol's entry now matches no pool */
    struct ifconfig_pool *g2 = make_pool(GLOBAL_START, GLOBAL_END);
    struct ifconfig_pool *a2 = make_pool(A_START, A_END);
    struct ifconfig_pool *pools2[] = { g2, a2 };
    struct ifconfig_pool_persist *rp = ifconfig_pool_persist_init(persist_file, 0);
    ifconfig_pool_read(rp, pools2, 2);
    ifconfig_pool_persist_close(rp);

    assert_string_equal(g2->list[0].common_name, "alice");
    assert_string_equal(a2->list[0].common_name, "bob");
    assert_false(pool_has_cn(g2, "carol"));
    assert_false(pool_has_cn(a2, "carol"));

    ifconfig_pool_free(g);
    ifconfig_pool_free(a);
    ifconfig_pool_free(b);
    ifconfig_pool_free(g2);
    ifconfig_pool_free(a2);
}

const struct CMUnitTest pool_tests[] = {
    cmocka_unit_test(test_persist_roundtrip),
    cmocka_unit_test(test_persist_ignore_unknown),
};

int
main(void)
{
    struct gc_arena gc = gc_new();

    persist_file = platform_create_temp_file(NULL, "pool_persist_ut", &gc);
    assert_non_null(persist_file);

    openvpn_unit_test_setup();
    int ret = cmocka_run_group_tests(pool_tests, NULL, NULL);

    platform_unlink(persist_file);
    gc_free(&gc);
    return ret;
}
