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
#include "mock_msg.h"

/* --subnet-pool-tag resolves a client to its --subnet-pool; an unknown tag
 * returns NULL, which is what makes the server reject that client. */
static void
test_subnet_pool_by_tag(void **state)
{
    struct subnet_pool_def c = { .next = NULL, .tag = "grpC", .network = 0x0a020300, .netmask = 0xffffff00, .gateway = 0x0a020301 };
    struct subnet_pool_def b = { .next = &c, .tag = "grpB", .network = 0x0a020200, .netmask = 0xffffff00, .gateway = 0x0a020201 };
    struct subnet_pool_def a = { .next = &b, .tag = "grpA", .network = 0x0a020100, .netmask = 0xffffff00, .gateway = 0x0a020101 };

    /* every configured tag resolves to its own pool, wherever it sits */
    assert_ptr_equal(subnet_pool_by_tag(&a, "grpA"), &a);
    assert_ptr_equal(subnet_pool_by_tag(&a, "grpB"), &b);
    assert_ptr_equal(subnet_pool_by_tag(&a, "grpC"), &c);

    /* and it carries that pool's subnet/gateway */
    const struct subnet_pool_def *r = subnet_pool_by_tag(&a, "grpB");
    assert_int_equal(r->network, 0x0a020200);
    assert_int_equal(r->netmask, 0xffffff00);
    assert_int_equal(r->gateway, 0x0a020201);

    /* unknown tag and empty list both miss */
    assert_null(subnet_pool_by_tag(&a, "nope"));
    assert_null(subnet_pool_by_tag(NULL, "grpA"));
}

/* the IPv6 counterpart resolves independently: a tag may name a v4 pool, a
 * v6 pool, or both. */
static void
test_subnet_pool6_by_tag(void **state)
{
    struct subnet_pool6_def c = { .next = NULL, .tag = "grpC", .netbits = 64 };
    struct subnet_pool6_def b = { .next = &c, .tag = "grpB", .netbits = 96 };
    struct subnet_pool6_def a = { .next = &b, .tag = "grpA", .netbits = 64 };

    assert_ptr_equal(subnet_pool6_by_tag(&a, "grpA"), &a);
    assert_ptr_equal(subnet_pool6_by_tag(&a, "grpB"), &b);
    assert_ptr_equal(subnet_pool6_by_tag(&a, "grpC"), &c);
    assert_int_equal(subnet_pool6_by_tag(&a, "grpB")->netbits, 96);
    assert_null(subnet_pool6_by_tag(&a, "nope"));
    assert_null(subnet_pool6_by_tag(NULL, "grpA"));
}

const struct CMUnitTest subnet_pool_tests[] = {
    cmocka_unit_test(test_subnet_pool_by_tag),
    cmocka_unit_test(test_subnet_pool6_by_tag),
};

int
main(void)
{
    openvpn_unit_test_setup();
    return cmocka_run_group_tests(subnet_pool_tests, NULL, NULL);
}
