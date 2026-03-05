/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2025-2026 OpenVPN Inc <sales@openvpn.net>
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

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <setjmp.h>
#include <cmocka.h>

#include "options.h"
#include "options_util.h"
#include "test_common.h"
#include "mock_msg.h"

void
add_option(struct options *options, char *p[], bool is_inline, const char *file,
           int line, const int level, const msglvl_t msglevel,
           const unsigned int permission_mask, unsigned int *option_types_found,
           struct env_set *es)
{
    function_called();
    check_expected_ptr(p);
    check_expected_uint(is_inline);
}

void
remove_option(struct context *c, struct options *options, char *p[], bool is_inline,
              const char *file, int line, const msglvl_t msglevel,
              const unsigned int permission_mask, unsigned int *option_types_found,
              struct env_set *es)
{
}

void
update_option(struct context *c, struct options *options, char *p[], bool is_inline,
              const char *file, int line, const int level, const msglvl_t msglevel,
              const unsigned int permission_mask, unsigned int *option_types_found,
              struct env_set *es)
{
}

void
usage(void)
{
}

/* for building long texts */
#define A_TIMES_256 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAO"

static void
test_parse_line(void **state)
{
    char *p[MAX_PARMS + 1] = { 0 };
    struct gc_arena gc = gc_new();
    int res = 0;

#define PARSE_LINE_TST(string)                                                          \
    do                                                                                  \
    {                                                                                   \
        CLEAR(p);                                                                       \
        res = parse_line(string, p, SIZE(p) - 1, "test_options_parse", 1, M_INFO, &gc); \
    } while (0);

    /* basic example */
    PARSE_LINE_TST("some-opt firstparm second-parm");
    assert_int_equal(res, 3);
    assert_string_equal(p[0], "some-opt");
    assert_string_equal(p[1], "firstparm");
    assert_string_equal(p[2], "second-parm");
    assert_null(p[res]);

    /* basic quoting, -- is not handled special */
    PARSE_LINE_TST("--some-opt 'first parm' \"second' 'parm\"");
    assert_int_equal(res, 3);
    assert_string_equal(p[0], "--some-opt");
    assert_string_equal(p[1], "first parm");
    assert_string_equal(p[2], "second' 'parm");
    assert_null(p[res]);

    /* escaped quotes */
    PARSE_LINE_TST("\"some opt\" 'first\" \"parm' \"second\\\" \\\"parm\"");
    assert_int_equal(res, 3);
    assert_string_equal(p[0], "some opt");
    assert_string_equal(p[1], "first\" \"parm");
    assert_string_equal(p[2], "second\" \"parm");
    assert_null(p[res]);

    /* missing closing quote */
    PARSE_LINE_TST("--some-opt 'first parm \"second parm\"");
    assert_int_equal(res, 0);

    /* escaped backslash */
    PARSE_LINE_TST("some\\\\opt C:\\\\directory\\\\file");
    assert_int_equal(res, 2);
    assert_string_equal(p[0], "some\\opt");
    assert_string_equal(p[1], "C:\\directory\\file");
    assert_null(p[res]);

    /* comment chars are not special inside parameter */
    PARSE_LINE_TST("some-opt firstparm; second#parm");
    assert_int_equal(res, 3);
    assert_string_equal(p[0], "some-opt");
    assert_string_equal(p[1], "firstparm;");
    assert_string_equal(p[2], "second#parm");
    assert_null(p[res]);

    /* comment */
    PARSE_LINE_TST("some-opt firstparm # secondparm");
    assert_int_equal(res, 2);
    assert_string_equal(p[0], "some-opt");
    assert_string_equal(p[1], "firstparm");
    assert_null(p[res]);

    /* parameter just long enough */
    PARSE_LINE_TST("opt " A_TIMES_256);
    assert_int_equal(res, 2);
    assert_string_equal(p[0], "opt");
    assert_string_equal(p[1], A_TIMES_256);
    assert_null(p[res]);

    /* quoting doesn't count for parameter length */
    PARSE_LINE_TST("opt \"" A_TIMES_256 "\"");
    assert_int_equal(res, 2);
    assert_string_equal(p[0], "opt");
    assert_string_equal(p[1], A_TIMES_256);
    assert_null(p[res]);

    /* very long line */
    PARSE_LINE_TST("opt " A_TIMES_256 " " A_TIMES_256 " " A_TIMES_256 " " A_TIMES_256);
    assert_int_equal(res, 5);
    assert_string_equal(p[0], "opt");
    assert_string_equal(p[1], A_TIMES_256);
    assert_string_equal(p[2], A_TIMES_256);
    assert_string_equal(p[3], A_TIMES_256);
    assert_string_equal(p[4], A_TIMES_256);
    assert_null(p[res]);

    /* parameter too long */
    PARSE_LINE_TST("opt " A_TIMES_256 "B");
    assert_int_equal(res, 0);

    /* max parameters */
    PARSE_LINE_TST("0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15");
    assert_int_equal(res, MAX_PARMS);
    char num[3];
    for (int i = 0; i < MAX_PARMS; i++)
    {
        assert_true(snprintf(num, 3, "%d", i) < 3);
        assert_string_equal(p[i], num);
    }
    assert_null(p[res]);

    /* too many parameters, overflow is ignored */
    PARSE_LINE_TST("0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16");
    assert_int_equal(res, MAX_PARMS);
    for (int i = 0; i < MAX_PARMS; i++)
    {
        assert_true(snprintf(num, 3, "%d", i) < 3);
        assert_string_equal(p[i], num);
    }
    assert_null(p[res]);

    gc_free(&gc);
}

static void
read_single_config(struct options *options, const char *config)
{
    unsigned int option_types_found = 0;
    struct env_set es;
    CLEAR(es);
    read_config_string("test_options_parse", options, config, M_INFO, OPT_P_DEFAULT,
                       &option_types_found, &es);
}

#if HAVE_OLD_CMOCKA_API
union token_parameter
{
    LargestIntegralType int_val;
    void *ptr;
};
#endif

static int
check_tokens(const CMockaValueData value, const CMockaValueData expected)
{
#if HAVE_OLD_CMOCKA_API
    union token_parameter temp;
    temp.int_val = value;
    const char **p = (const char **)temp.ptr;
    temp.int_val = expected;
    const char **expected_p = (const char **)temp.ptr;
#else
    const char **p = (const char **)value.ptr;
    const char **expected_p = (const char **)expected.ptr;
#endif
    for (int i = 0; i < MAX_PARMS; i++)
    {
        if (!p[i] && !expected_p[i])
        {
            return true;
        }
        if ((p[i] && !expected_p[i])
            || (!p[i] && expected_p[i]))
        {
            fprintf(stderr, "diff at i=%d\n", i);
            return false;
        }
        if (strcmp(p[i], expected_p[i]))
        {
            fprintf(stderr, "diff at i=%d, p=<%s> ep=<%s>\n", i, p[i], expected_p[i]);
            return false;
        }
    }
    fprintf(stderr, "fallthrough");
    return false;
}

static void
test_read_config(void **state)
{
    struct options o;
    CLEAR(o); /* NB: avoiding init_options to limit dependencies */
    gc_init(&o.gc);
    gc_init(&o.dns_options.gc);

    char *p_expect_someopt[MAX_PARMS] = { "someopt", "parm1", "parm2", NULL };
    char *p_expect_otheropt[MAX_PARMS] = { "otheropt", "1", "2", NULL };
    char *p_expect_inlineopt[MAX_PARMS] = { "inlineopt", "some text\nother text\n", NULL };

    /* basic test */
    expect_function_call(add_option);
    expect_check_data(add_option, p, check_tokens, cast_ptr_to_cmocka_value(p_expect_someopt));
    expect_uint_value(add_option, is_inline, 0);
    expect_function_call(add_option);
    expect_check_data(add_option, p, check_tokens, cast_ptr_to_cmocka_value(p_expect_otheropt));
    expect_uint_value(add_option, is_inline, 0);
    read_single_config(&o, "someopt parm1 parm2\n  otheropt 1 2");

    /* -- gets stripped */
    expect_function_call(add_option);
    expect_check_data(add_option, p, check_tokens, cast_ptr_to_cmocka_value(p_expect_someopt));
    expect_uint_value(add_option, is_inline, 0);
    expect_function_call(add_option);
    expect_check_data(add_option, p, check_tokens, cast_ptr_to_cmocka_value(p_expect_otheropt));
    expect_uint_value(add_option, is_inline, 0);
    read_single_config(&o, "someopt parm1 parm2\n\t--otheropt 1 2");

    /* inline options */
    expect_function_call(add_option);
    expect_check_data(add_option, p, check_tokens, cast_ptr_to_cmocka_value(p_expect_inlineopt));
    expect_uint_value(add_option, is_inline, 1);
    read_single_config(&o, "<inlineopt>\nsome text\nother text\n</inlineopt>");

    p_expect_inlineopt[0] = "inlineopt";
    p_expect_inlineopt[1] = A_TIMES_256 A_TIMES_256 A_TIMES_256 A_TIMES_256 A_TIMES_256 "\n";
    expect_function_call(add_option);
    expect_check_data(add_option, p, check_tokens, cast_ptr_to_cmocka_value(p_expect_inlineopt));
    expect_uint_value(add_option, is_inline, 1);
    read_single_config(&o, "<inlineopt>\n" A_TIMES_256 A_TIMES_256 A_TIMES_256 A_TIMES_256 A_TIMES_256 "\n</inlineopt>");

    gc_free(&o.gc);
    gc_free(&o.dns_options.gc);
}

static void
assert_tokens(char *actual[], const char *expected[], int max_idx)
{
    for (int i = 0; i <= max_idx + 1; ++i)
    {
        if (!expected[i])
        {
            assert_null(actual[i]);
            continue;
        }
        assert_non_null(actual[i]);
        assert_string_equal(actual[i], expected[i]);
    }
}

static void
test_convert_ipv4_cidr_parms_core(void **state)
{
    struct gc_arena gc = gc_new();
    char *normalized[MAX_PARMS + 1] = { 0 };

    /* non-CIDR input is returned unchanged */
    char *legacy[MAX_PARMS + 1] = { "route", "10.8.0.0", "255.255.255.0", NULL };
    const char *legacy_expected[] = { "route", "10.8.0.0", "255.255.255.0", NULL, NULL, NULL };
    assert_int_equal(convert_ipv4_cidr_parms(legacy, 1, 4, normalized, &gc), 0);
    assert_tokens(normalized, legacy_expected, 4);

    /* CIDR input is split and netmask is materialized */
    CLEAR(normalized);
    char *cidr[MAX_PARMS + 1] = { "route", "10.8.0.0/24", NULL };
    const char *cidr_expected[] = { "route", "10.8.0.0", "255.255.255.0", NULL, NULL, NULL };
    assert_int_equal(convert_ipv4_cidr_parms(cidr, 1, 4, normalized, &gc), 1);
    assert_tokens(normalized, cidr_expected, 4);

    gc_free(&gc);
}

static void
test_convert_ipv4_cidr_parms_coverage(void **state)
{
    struct gc_arena gc = gc_new();
    char *normalized[MAX_PARMS + 1] = { 0 };

    /* success paths */

    /* route */
    char *route[] = { "route", "10.1.2.0/24", "192.0.2.1", "7", NULL };
    const char *route_expected[] = { "route", "10.1.2.0", "255.255.255.0", "192.0.2.1", "7",
                                     NULL };
    assert_int_equal(convert_ipv4_cidr_parms(route, 1, 4, normalized, &gc), 1);
    assert_tokens(normalized, route_expected, 4);

    /* ifconfig */
    CLEAR(normalized);
    char *ifconfig[] = { "ifconfig", "10.8.0.1/24", NULL };
    const char *ifconfig_expected[] = { "ifconfig", "10.8.0.1", "255.255.255.0", NULL };
    assert_int_equal(convert_ipv4_cidr_parms(ifconfig, 1, 2, normalized, &gc), 1);
    assert_tokens(normalized, ifconfig_expected, 2);

    /* server */
    CLEAR(normalized);
    char *server[] = { "server", "10.8.0.0/24", "nopool", NULL };
    const char *server_expected[] = { "server", "10.8.0.0", "255.255.255.0", "nopool", NULL };
    assert_int_equal(convert_ipv4_cidr_parms(server, 1, 3, normalized, &gc), 1);
    assert_tokens(normalized, server_expected, 3);

    /* server-bridge */
    CLEAR(normalized);
    char *server_bridge[] = { "server-bridge", "10.8.0.1/24", "10.8.0.10", "10.8.0.20", NULL };
    const char *server_bridge_expected[] = { "server-bridge", "10.8.0.1", "255.255.255.0",
                                             "10.8.0.10", "10.8.0.20", NULL };
    assert_int_equal(convert_ipv4_cidr_parms(server_bridge, 1, 4, normalized, &gc), 1);
    assert_tokens(normalized, server_bridge_expected, 4);

    /* iroute */
    CLEAR(normalized);
    char *iroute[] = { "iroute", "172.16.0.0/16", NULL };
    const char *iroute_expected[] = { "iroute", "172.16.0.0", "255.255.0.0", NULL };
    assert_int_equal(convert_ipv4_cidr_parms(iroute, 1, 2, normalized, &gc), 1);
    assert_tokens(normalized, iroute_expected, 2);

    /* ifconfig-push */
    CLEAR(normalized);
    char *ifconfig_push[] = { "ifconfig-push", "10.8.0.6/24", "10.8.0.7", NULL };
    const char *ifconfig_push_expected[] = { "ifconfig-push", "10.8.0.6", "255.255.255.0",
                                             "10.8.0.7", NULL };
    assert_int_equal(convert_ipv4_cidr_parms(ifconfig_push, 1, 3, normalized, &gc), 1);
    assert_tokens(normalized, ifconfig_push_expected, 3);

    /* ifconfig-push-constraint */
    CLEAR(normalized);
    char *ifconfig_push_constraint[] = { "ifconfig-push-constraint", "10.8.0.0/24", NULL };
    const char *ifconfig_push_constraint_expected[] = { "ifconfig-push-constraint", "10.8.0.0",
                                                        "255.255.255.0", NULL };
    assert_int_equal(convert_ipv4_cidr_parms(ifconfig_push_constraint, 1, 2, normalized, &gc),
                     1);
    assert_tokens(normalized, ifconfig_push_constraint_expected, 2);

    /* client-nat */
    CLEAR(normalized);
    char *client_nat[] = { "client-nat", "snat", "192.168.0.0/16", "10.0.0.0", NULL };
    const char *client_nat_expected[] = { "client-nat", "snat", "192.168.0.0", "255.255.0.0",
                                          "10.0.0.0", NULL };
    assert_int_equal(convert_ipv4_cidr_parms(client_nat, 2, 4, normalized, &gc), 1);
    assert_tokens(normalized, client_nat_expected, 4);

    /* CIDR prefix boundaries */

    /* /0 */
    CLEAR(normalized);
    char *route_default[MAX_PARMS + 1] = { "route", "0.0.0.0/0", NULL };
    const char *route_default_expected[] = { "route", "0.0.0.0", "0.0.0.0", NULL, NULL, NULL };
    assert_int_equal(convert_ipv4_cidr_parms(route_default, 1, 4, normalized, &gc), 1);
    assert_tokens(normalized, route_default_expected, 4);

    /* /32 */
    CLEAR(normalized);
    char *route_host[MAX_PARMS + 1] = { "route", "198.51.100.42/32", NULL };
    const char *route_host_expected[] = { "route", "198.51.100.42", "255.255.255.255", NULL,
                                          NULL, NULL };
    assert_int_equal(convert_ipv4_cidr_parms(route_host, 1, 4, normalized, &gc), 1);
    assert_tokens(normalized, route_host_expected, 4);

    /* CIDR with DNS-style network token */
    CLEAR(normalized);
    char *route_dns_cidr[] = { "route", "vpn.example/24", "192.0.2.1", NULL };
    const char *route_dns_cidr_expected[] = { "route", "vpn.example", "255.255.255.0",
                                              "192.0.2.1", NULL, NULL };
    assert_int_equal(convert_ipv4_cidr_parms(route_dns_cidr, 1, 4, normalized, &gc), 1);
    assert_tokens(normalized, route_dns_cidr_expected, 4);

    /* non-CIDR passthrough (DNS-style network token) */
    CLEAR(normalized);
    char *route_dns[] = { "route", "vpn.example", "255.255.255.0", "192.0.2.1", NULL };
    const char *route_dns_expected[] = { "route", "vpn.example", "255.255.255.0", "192.0.2.1",
                                         NULL, NULL };
    assert_int_equal(convert_ipv4_cidr_parms(route_dns, 1, 4, normalized, &gc), 0);
    assert_tokens(normalized, route_dns_expected, 4);

    /* varied network_idx/max_idx shapes */

    CLEAR(normalized);
    char *generic_shift[] = { "opt", "x", "y", "10.9.0.0/25", "tail", NULL };
    const char *generic_shift_expected[] = { "opt", "x", "y", "10.9.0.0", "255.255.255.128",
                                             "tail", NULL };
    assert_int_equal(convert_ipv4_cidr_parms(generic_shift, 3, 5, normalized, &gc), 1);
    assert_tokens(normalized, generic_shift_expected, 5);

    CLEAR(normalized);
    char *near_limit[MAX_PARMS + 1] = { 0 };
    near_limit[0] = "opt";
    near_limit[MAX_PARMS - 2] = "203.0.113.0/24";
    assert_int_equal(
        convert_ipv4_cidr_parms(near_limit, MAX_PARMS - 2, MAX_PARMS - 1, normalized, &gc), 1);
    assert_string_equal(normalized[0], "opt");
    assert_string_equal(normalized[MAX_PARMS - 2], "203.0.113.0");
    assert_string_equal(normalized[MAX_PARMS - 1], "255.255.255.0");
    assert_null(normalized[MAX_PARMS]);

    /* error paths */

    char *route_invalid[] = { "route", "10.1.2.0/33", NULL };
    assert_int_equal(convert_ipv4_cidr_parms(route_invalid, 1, 4, normalized, &gc), -EINVAL);
    char *route_invalid_negative_prefix[] = { "route", "10.1.2.0/-1", NULL };
    assert_int_equal(convert_ipv4_cidr_parms(route_invalid_negative_prefix, 1, 4, normalized,
                                             &gc),
                     -EINVAL);
    char *route_invalid_plus_prefix[] = { "route", "10.1.2.0/+24", NULL };
    assert_int_equal(convert_ipv4_cidr_parms(route_invalid_plus_prefix, 1, 4, normalized, &gc),
                     -EINVAL);
    char *route_invalid_malformed_slash[] = { "route", "10.1.2.0//24", NULL };
    assert_int_equal(convert_ipv4_cidr_parms(route_invalid_malformed_slash, 1, 4, normalized,
                                             &gc),
                     -EINVAL);
    char *route_invalid_overflow_prefix[] = { "route", "10.1.2.0/999999999999999999999", NULL };
    assert_int_equal(convert_ipv4_cidr_parms(route_invalid_overflow_prefix, 1, 4, normalized,
                                             &gc),
                     -EINVAL);
    char *route_invalid_empty_network[] = { "route", "/24", NULL };
    assert_int_equal(convert_ipv4_cidr_parms(route_invalid_empty_network, 1, 4, normalized, &gc),
                     -EINVAL);
    char *route_invalid_no_prefix[] = { "route", "10.1.2.0/", NULL };
    assert_int_equal(convert_ipv4_cidr_parms(route_invalid_no_prefix, 1, 4, normalized, &gc),
                     -EINVAL);
    char *route_invalid_alpha_prefix[] = { "route", "10.1.2.0/2x", NULL };
    assert_int_equal(convert_ipv4_cidr_parms(route_invalid_alpha_prefix, 1, 4, normalized, &gc),
                     -EINVAL);

    char *client_nat_invalid[] = { "client-nat", "snat", "192.168.0.0/35", "10.0.0.0", NULL };
    assert_int_equal(convert_ipv4_cidr_parms(client_nat_invalid, 2, 4, normalized, &gc),
                     -EINVAL);

    gc_free(&gc);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_parse_line),
        cmocka_unit_test(test_read_config),
        cmocka_unit_test(test_convert_ipv4_cidr_parms_core),
        cmocka_unit_test(test_convert_ipv4_cidr_parms_coverage),
    };

    return cmocka_run_group_tests_name("options_parse", tests, NULL, NULL);
}
