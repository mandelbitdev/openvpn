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

#include "options.h"
#include "options_util.h"
#include "test_common.h"
#include "test_subnet_pool.h"
#include "mock_msg.h"

/* --subnet-pool-name resolves a client to its --subnet-pool; an unknown name
 * returns NULL, which is what makes the server reject that client. */
void
test_subnet_pool_by_name(void **state)
{
    struct subnet_pool_def c = { .next = NULL, .name = "grpC", .network = 0x0a020300, .netmask = 0xffffff00, .gateway = 0x0a020301 };
    struct subnet_pool_def b = { .next = &c, .name = "grpB", .network = 0x0a020200, .netmask = 0xffffff00, .gateway = 0x0a020201 };
    struct subnet_pool_def a = { .next = &b, .name = "grpA", .network = 0x0a020100, .netmask = 0xffffff00, .gateway = 0x0a020101 };

    /* every configured name resolves to its own pool, wherever it sits */
    assert_ptr_equal(subnet_pool_by_name(&a, "grpA"), &a);
    assert_ptr_equal(subnet_pool_by_name(&a, "grpB"), &b);
    assert_ptr_equal(subnet_pool_by_name(&a, "grpC"), &c);

    /* and it carries that pool's subnet/gateway */
    const struct subnet_pool_def *r = subnet_pool_by_name(&a, "grpB");
    assert_int_equal(r->network, 0x0a020200);
    assert_int_equal(r->netmask, 0xffffff00);
    assert_int_equal(r->gateway, 0x0a020201);

    /* unknown name and empty list both miss */
    assert_null(subnet_pool_by_name(&a, "nope"));
    assert_null(subnet_pool_by_name(NULL, "grpA"));
}

/* a single pool <net>/<mask> with gateway <gw>, checked against the
 * 10.8.0.0/24 --server network */
static bool
check_one(in_addr_t net, in_addr_t mask, in_addr_t gw)
{
    struct subnet_pool_def d = { .next = NULL, .name = "grp", .network = net, .netmask = mask, .gateway = gw };

    return subnet_pools_check(&d, 0x0a080000, 0xffffff00, M_WARN);
}

/* --subnet-pool geometry: anything ifconfig_pool_init() cannot serve must be
 * refused when the config is checked, not when the first client connects */
void
test_subnet_pools_check_netmask(void **state)
{
    /* the bounds of --server: /16 .. /29 */
    assert_true(check_one(0x0a090000, 0xffff0000, 0x0a090001));
    assert_true(check_one(0x0a090000, 0xffffff00, 0x0a090001));
    assert_true(check_one(0x0a090000, 0xfffffff8, 0x0a090001));
    /* /30, /31, /32: too few addresses for a pool */
    assert_false(check_one(0x0a090000, 0xfffffffc, 0x0a090001));
    assert_false(check_one(0x0a090000, 0xfffffffe, 0x0a090001));
    assert_false(check_one(0x0a090000, 0xffffffff, 0x0a090000));
    /* /15: larger than IFCONFIG_POOL_MAX */
    assert_false(check_one(0x0a080000, 0xfffe0000, 0x0a080001));
    /* non-contiguous netmask */
    assert_false(check_one(0x0a000900, 0xff00ff00, 0x0a000901));
}

void
test_subnet_pools_check_gateway(void **state)
{
    /* any host address of the subnet is fine, not only the first one */
    assert_true(check_one(0x0a090000, 0xffffff00, 0x0a0900fe));
    assert_true(check_one(0x0a090000, 0xffffff00, 0x0a090080));
    /* network address, broadcast address, outside the subnet */
    assert_false(check_one(0x0a090000, 0xffffff00, 0x0a090000));
    assert_false(check_one(0x0a090000, 0xffffff00, 0x0a0900ff));
    assert_false(check_one(0x0a090000, 0xffffff00, 0x0a0a0001));
}

/* a 10.9.0.0/24 pool with dynamic range <start>-<end> */
static bool
check_range(in_addr_t start, in_addr_t end)
{
    struct subnet_pool_def d = { .next = NULL, .name = "grp", .network = 0x0a090000, .netmask = 0xffffff00, .gateway = 0x0a090001, .pool_start = start, .pool_end = end };

    return subnet_pools_check(&d, 0x0a080000, 0xffffff00, M_WARN);
}

/* the optional dynamic range: host addresses of the subnet, at least 2 */
void
test_subnet_pools_check_range(void **state)
{
    /* unset: the whole subnet */
    assert_true(check_range(0, 0));
    /* a sub-range, the smallest one, the whole host range */
    assert_true(check_range(0x0a090064, 0x0a0900c8));
    assert_true(check_range(0x0a090064, 0x0a090065));
    assert_true(check_range(0x0a090001, 0x0a0900fe));
    /* a single address, or start past end */
    assert_false(check_range(0x0a090064, 0x0a090064));
    assert_false(check_range(0x0a0900c8, 0x0a090064));
    /* the network or broadcast address */
    assert_false(check_range(0x0a090000, 0x0a090064));
    assert_false(check_range(0x0a090064, 0x0a0900ff));
    /* outside the subnet */
    assert_false(check_range(0x0a090064, 0x0a0a0001));
    assert_false(check_range(0x0a080064, 0x0a090064));
}

void
test_subnet_pools_check_overlap(void **state)
{
    struct subnet_pool_def b = { .next = NULL, .name = "grpB", .network = 0x0a0a0000, .netmask = 0xffffff00, .gateway = 0x0a0a0001 };
    struct subnet_pool_def a = { .next = &b, .name = "grpA", .network = 0x0a090000, .netmask = 0xffffff00, .gateway = 0x0a090001 };

    /* disjoint pools, disjoint from --server */
    assert_true(subnet_pools_check(&a, 0x0a080000, 0xffffff00, M_WARN));

    /* a pool inside the --server network ... */
    assert_false(subnet_pools_check(&a, 0x0a090000, 0xffffff00, M_WARN));
    /* ... or covering it */
    assert_false(subnet_pools_check(&a, 0x0a0a0080, 0xffffff80, M_WARN));
    /* no --server network: only the pools are checked against each other */
    assert_true(subnet_pools_check(&a, 0, 0, M_WARN));

    /* a /16 grpB containing grpA */
    struct subnet_pool_def b16 = { .next = NULL, .name = "grpB", .network = 0x0a090000, .netmask = 0xffff0000, .gateway = 0x0a090101 };
    struct subnet_pool_def a16 = { .next = &b16, .name = "grpA", .network = 0x0a090000, .netmask = 0xffffff00, .gateway = 0x0a090001 };
    assert_false(subnet_pools_check(&a16, 0, 0, M_WARN));

    /* the same name defined twice */
    struct subnet_pool_def bdup = { .next = NULL, .name = "grpA", .network = 0x0a0a0000, .netmask = 0xffffff00, .gateway = 0x0a0a0001 };
    struct subnet_pool_def adup = { .next = &bdup, .name = "grpA", .network = 0x0a090000, .netmask = 0xffffff00, .gateway = 0x0a090001 };
    assert_false(subnet_pools_check(&adup, 0, 0, M_WARN));
}
