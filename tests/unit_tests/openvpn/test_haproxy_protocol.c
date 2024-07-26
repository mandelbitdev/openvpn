#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"

#include <setjmp.h>
#include <cmocka.h>

#include "platform.h"
#include "buffer.h"
#include "haproxy_protocol.h"
#include "test_common.h"

extern uint32_t
haproxy_protocol_crc32c(const uint8_t *data, int len);

/* header building blocks */
#define HP1_SIG           0x50, 0x52, 0x4f, 0x58, 0x59 /* "PROXY" */
#define HP1_TCP4_AF_UNKN  0x55, 0x4E, 0x4B, 0x4E, 0x4F, 0x57, 0x4E /* "UNKNOWN" */
#define HP1_TCP4_AF_INET  0x54, 0x43, 0x50, 0x34 /* "TCP4" */
#define HP1_TCP6_AF_INET  0x54, 0x43, 0x50, 0x36 /* "TCP6" */
#define HP1_TCP4_SRC_ADDR 0x31, 0x30, 0x2e, 0x31, 0x30, 0x2e, 0x32, 0x30, 0x2e, 0x32 /* "10.10.20.2" */
#define HP1_TCP4_DST_ADDR 0x31, 0x30, 0x2e, 0x31, 0x30, 0x2e, 0x32, 0x30, 0x2e, 0x31 /* "10.10.20.1" */
#define HP1_TCP4_SRC_PORT 0x34, 0x30, 0x31, 0x35, 0x30 /* 40150 */
#define HP1_TCP4_DST_PORT 0x31, 0x31, 0x39, 0x35 /* 1195 */
#define HP1_TCP6_SRC_ADDR 0x32, 0x30, 0x30, 0x31, 0x3a, 0x64, 0x62, 0x38, 0x3a, 0x32, 0x30, 0x3a, 0x3a, 0x32 /* "2001:db8:20::2" */
#define HP1_TCP6_DST_ADDR 0x32, 0x30, 0x30, 0x31, 0x3a, 0x64, 0x62, 0x38, 0x3a, 0x32, 0x30, 0x3a, 0x3a, 0x31 /* "2001:db8:20::1" */
#define HP1_TCP6_SRC_PORT 0x35, 0x33, 0x33, 0x34, 0x34 /* 53344 */
#define HP1_TCP6_DST_PORT 0x31, 0x31, 0x39, 0x35 /* 1195 */
#define HP1_END           0x0d, 0x0a /* "\r\n" */

#define HP2_SIG         0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a /* "\r\n\r\n\x00\r\nQUIT\n" */
#define HP2_V4_SRC_ADDR 0x0a, 0x0a, 0x14, 0x02 /* 10.10.20.2 */
#define HP2_V4_DST_ADDR 0x0a, 0x0a, 0x14, 0x01 /* 10.10.20.1 */
#define HP2_V4_SRC_PORT 0xa5, 0x30 /* 42288 */
#define HP2_V4_DST_PORT 0x04, 0xab /* 1195 */
#define HP2_V6_SRC_ADDR 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 /* 2001:db8:20::2 */
#define HP2_V6_DST_ADDR 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 /* 2001:db8:20::1 */
#define HP2_V6_SRC_PORT 0xe8, 0xb6 /* 59574 */
#define HP2_V6_DST_PORT 0x04, 0xab /* 1195 */
#define HP2_TLV \
    0x01, 0x00, 0x03, 'h', '2', '3', \
    0x02, 0x00, 0x0b, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', \
    0x04, 0x00, 0x00, \
    0x05, 0x00, 0x0f, 'u', 'n', 'i', 'q', 'u', 'e', '-', 'i', 'd', '-', 'v', 'a', 'l', 'u', 'e', \
    0x20, 0x00, 0x33, 0x01, 0x00, 0x00, 0x00, 0x00, \
    0x21, 0x00, 0x06, 'T', 'L', 'S', '1', '.', '3', \
    0x22, 0x00, 0x06, 'c', 'l', 'i', 'e', 'n', 't', \
    0x23, 0x00, 0x06, 'A', 'E', 'S', '2', '5', '6', \
    0x24, 0x00, 0x06, 'S', 'H', 'A', '2', '5', '6', \
    0x25, 0x00, 0x07, 'R', 'S', 'A', '2', '0', '4', '8', \
    0x30, 0x00, 0x07, 'n', 'e', 't', 'n', 's', '-', '1'

#define HP_TEST_OPENVPN \
    0x00, 0x0e, 0x38, 0xa8, 0xf5, 0x24, 0xa0, 0xa7, \
    0x89, 0x00, 0xca, 0x00, 0x00, 0x00, 0x00, 0x00

/* headers */
static uint8_t HP1_TEST_UNKNOWN[] = {
    HP1_SIG, 0x20, HP1_TCP4_AF_UNKN, HP1_END
};

static uint8_t HP1_TEST_TCP4[] = {
    HP1_SIG, 0x20,
    HP1_TCP4_AF_INET, 0x20,
    HP1_TCP4_SRC_ADDR, 0x20,
    HP1_TCP4_DST_ADDR, 0x20,
    HP1_TCP4_SRC_PORT, 0x20,
    HP1_TCP4_DST_PORT,
    HP1_END
};

static uint8_t HP1_TEST_TCP4_PLUS_OPENVPN[] = {
    HP1_SIG, 0x20,
    HP1_TCP4_AF_INET, 0x20,
    HP1_TCP4_SRC_ADDR, 0x20,
    HP1_TCP4_DST_ADDR, 0x20,
    HP1_TCP4_SRC_PORT, 0x20,
    HP1_TCP4_DST_PORT,
    HP1_END,
    HP_TEST_OPENVPN
};

static uint8_t HP1_TEST_TCP6[] = {
    HP1_SIG, 0x20,
    HP1_TCP6_AF_INET, 0x20,
    HP1_TCP6_SRC_ADDR, 0x20,
    HP1_TCP6_DST_ADDR, 0x20,
    HP1_TCP6_SRC_PORT, 0x20,
    HP1_TCP6_DST_PORT,
    HP1_END
};

static uint8_t HP1_TEST_TCP6_PLUS_OPENVPN[] = {
    HP1_SIG, 0x20,
    HP1_TCP6_AF_INET, 0x20,
    HP1_TCP6_SRC_ADDR, 0x20,
    HP1_TCP6_DST_ADDR, 0x20,
    HP1_TCP6_SRC_PORT, 0x20,
    HP1_TCP6_DST_PORT,
    HP1_END,
    HP_TEST_OPENVPN
};

static uint8_t HP2_TEST_LOCAL[] = {
    HP2_SIG,
    HAPROXY_PROTOCOL_V2_VER | HAPROXY_PROTOCOL_V2_LOCAL_CMD,
    HAPROXY_PROTOCOL_V2_AF_UNSPEC | HAPROXY_PROTOCOL_V2_TP_UNSPEC,
    0x00, 0x00 /* length */
};

static uint8_t HP2_TEST_WRONG_VER[] = {
    HP2_SIG,
    0x10 | HAPROXY_PROTOCOL_V2_PROXY_CMD,
    HAPROXY_PROTOCOL_V2_AF_INET | HAPROXY_PROTOCOL_V2_TP_STREAM,
    0x00, 0x0c, /* length */
    HP2_V4_SRC_ADDR,
    HP2_V4_DST_ADDR,
    HP2_V4_SRC_PORT,
    HP2_V4_DST_PORT,
};

static uint8_t HP2_TEST_PROXY_TCP4[] = {
    HP2_SIG,
    HAPROXY_PROTOCOL_V2_VER | HAPROXY_PROTOCOL_V2_PROXY_CMD,
    HAPROXY_PROTOCOL_V2_AF_INET | HAPROXY_PROTOCOL_V2_TP_STREAM,
    0x00, 0x7c, /* length */
    HP2_V4_SRC_ADDR,
    HP2_V4_DST_ADDR,
    HP2_V4_SRC_PORT,
    HP2_V4_DST_PORT,
    HP2_TLV,
    0x03, 0x00, 0x04, 0x6e, 0x8a, 0xbf, 0x7f /* crc32c */
};

static uint8_t HP2_TEST_PROXY_TCP4_PLUS_OPENVPN[] = {
    HP2_SIG,
    HAPROXY_PROTOCOL_V2_VER | HAPROXY_PROTOCOL_V2_PROXY_CMD,
    HAPROXY_PROTOCOL_V2_AF_INET | HAPROXY_PROTOCOL_V2_TP_STREAM,
    0x00, 0x7c, /* length */
    HP2_V4_SRC_ADDR,
    HP2_V4_DST_ADDR,
    HP2_V4_SRC_PORT,
    HP2_V4_DST_PORT,
    HP2_TLV,
    0x03, 0x00, 0x04, 0x6e, 0x8a, 0xbf, 0x7f, /* crc32c */
    HP_TEST_OPENVPN
};

static uint8_t HP2_TEST_PROXY_TCP6[] = {
    HP2_SIG,
    HAPROXY_PROTOCOL_V2_VER | HAPROXY_PROTOCOL_V2_PROXY_CMD,
    HAPROXY_PROTOCOL_V2_AF_INET6 | HAPROXY_PROTOCOL_V2_TP_STREAM,
    0x00, 0x94, /* length */
    HP2_V6_SRC_ADDR,
    HP2_V6_DST_ADDR,
    HP2_V6_SRC_PORT,
    HP2_V6_DST_PORT,
    HP2_TLV,
    0x03, 0x00, 0x04, 0xed, 0xb0, 0x61, 0xb6 /* crc32c */
};

static uint8_t HP2_TEST_PROXY_TCP6_PLUS_OPENVPN[] = {
    HP2_SIG,
    HAPROXY_PROTOCOL_V2_VER | HAPROXY_PROTOCOL_V2_PROXY_CMD,
    HAPROXY_PROTOCOL_V2_AF_INET6 | HAPROXY_PROTOCOL_V2_TP_STREAM,
    0x00, 0x94, /* length */
    HP2_V6_SRC_ADDR,
    HP2_V6_DST_ADDR,
    HP2_V6_SRC_PORT,
    HP2_V6_DST_PORT,
    HP2_TLV,
    0x03, 0x00, 0x04, 0xed, 0xb0, 0x61, 0xb6, /* crc32c */
    HP_TEST_OPENVPN
};

static void
test_haproxy_protocol_version(void **state)
{
    assert_int_equal(haproxy_protocol_version(HP1_TEST_UNKNOWN, sizeof(HP1_TEST_UNKNOWN)), HAPROXY_PROTOCOL_VERSION_1);
    assert_int_equal(haproxy_protocol_version(HP1_TEST_TCP4, sizeof(HP1_TEST_TCP4)), HAPROXY_PROTOCOL_VERSION_1);
    assert_int_equal(haproxy_protocol_version(HP1_TEST_TCP6, sizeof(HP1_TEST_TCP6)), HAPROXY_PROTOCOL_VERSION_1);
    assert_int_equal(haproxy_protocol_version(HP2_TEST_WRONG_VER, sizeof(HP2_TEST_WRONG_VER)), HAPROXY_PROTOCOL_VERSION_2);
    assert_int_equal(haproxy_protocol_version(HP2_TEST_LOCAL, sizeof(HP2_TEST_LOCAL)), HAPROXY_PROTOCOL_VERSION_2);
    assert_int_equal(haproxy_protocol_version(HP2_TEST_PROXY_TCP4, sizeof(HP2_TEST_PROXY_TCP4)), HAPROXY_PROTOCOL_VERSION_2);
    assert_int_equal(haproxy_protocol_version(HP2_TEST_PROXY_TCP6, sizeof(HP2_TEST_PROXY_TCP6)), HAPROXY_PROTOCOL_VERSION_2);
    assert_int_equal(haproxy_protocol_version((uint8_t []){HP_TEST_OPENVPN}, sizeof((uint8_t []){HP_TEST_OPENVPN})), HAPROXY_PROTOCOL_VERSION_INVALID);
}

static void
test_haproxy_protocol_header_len(void **state)
{
    assert_int_equal(haproxy_protocol_header_len(HP1_TEST_UNKNOWN, sizeof(HP1_TEST_UNKNOWN), HAPROXY_PROTOCOL_VERSION_1), sizeof(HP1_TEST_UNKNOWN));
    assert_int_equal(haproxy_protocol_header_len(HP1_TEST_TCP4_PLUS_OPENVPN, sizeof(HP1_TEST_TCP4_PLUS_OPENVPN), HAPROXY_PROTOCOL_VERSION_1), sizeof(HP1_TEST_TCP4));
    assert_int_equal(haproxy_protocol_header_len(HP1_TEST_TCP6_PLUS_OPENVPN, sizeof(HP1_TEST_TCP6_PLUS_OPENVPN), HAPROXY_PROTOCOL_VERSION_1), sizeof(HP1_TEST_TCP6));
    assert_int_equal(haproxy_protocol_header_len(HP2_TEST_WRONG_VER, sizeof(HP2_TEST_WRONG_VER), HAPROXY_PROTOCOL_VERSION_2), sizeof(HP2_TEST_WRONG_VER));
    assert_int_equal(haproxy_protocol_header_len(HP2_TEST_LOCAL, sizeof(HP2_TEST_LOCAL), HAPROXY_PROTOCOL_VERSION_2), sizeof(HP2_TEST_LOCAL));
    assert_int_equal(haproxy_protocol_header_len(HP2_TEST_PROXY_TCP4_PLUS_OPENVPN, sizeof(HP2_TEST_PROXY_TCP4_PLUS_OPENVPN), HAPROXY_PROTOCOL_VERSION_2), sizeof(HP2_TEST_PROXY_TCP4));
    assert_int_equal(haproxy_protocol_header_len(HP2_TEST_PROXY_TCP6_PLUS_OPENVPN, sizeof(HP2_TEST_PROXY_TCP6_PLUS_OPENVPN), HAPROXY_PROTOCOL_VERSION_2), sizeof(HP2_TEST_PROXY_TCP6));
    assert_int_equal(haproxy_protocol_header_len((uint8_t []){HP_TEST_OPENVPN}, sizeof((uint8_t []){HP_TEST_OPENVPN}), HAPROXY_PROTOCOL_VERSION_INVALID), -1);
}

static bool
compare_hpi_basic(void **state, struct haproxy_protocol_info *actual, struct haproxy_protocol_info *expected)
{
    if (actual->src.addr.sa.sa_family != expected->src.addr.sa.sa_family
        || actual->dst.addr.sa.sa_family != expected->dst.addr.sa.sa_family)
    {
        return false;
    }

    switch (actual->src.addr.sa.sa_family)
    {
        case AF_INET:
            return actual->version == expected->version
                   && actual->sock_type == expected->sock_type
                   && memcmp(&actual->src.addr.in4.sin_addr, &expected->src.addr.in4.sin_addr, sizeof(struct in_addr)) == 0
                   && memcmp(&actual->dst.addr.in4.sin_addr, &expected->dst.addr.in4.sin_addr, sizeof(struct in_addr)) == 0
                   && actual->dst.addr.in4.sin_port == expected->dst.addr.in4.sin_port
                   && actual->src.addr.in4.sin_port == expected->src.addr.in4.sin_port;

        case AF_INET6:
            return actual->version == expected->version
                   && actual->sock_type == expected->sock_type
                   && memcmp(&actual->src.addr.in6, &expected->src.addr.in6, sizeof(struct sockaddr_in6)) == 0
                   && memcmp(&actual->dst.addr.in6, &expected->dst.addr.in6, sizeof(struct sockaddr_in6)) == 0;

        default:
            return false;
    }
}

static bool
compare_hpi(void **state, struct haproxy_protocol_info *actual, struct haproxy_protocol_info *expected)
{
    return compare_hpi_basic(state, actual, expected);
}

static int
setup_parse(void **state)
{
    struct haproxy_protocol_info *actual;
    ALLOC_OBJ_CLEAR(actual, struct haproxy_protocol_info);
    *state = actual;
    return 0;
}

static int
teardown_parse(void **state)
{
    haproxy_protocol_reset(*state);
    free(*state);
    return 0;
}

static void
test_haproxy_protocol_parse(void **state)
{
    struct haproxy_protocol_info *expected;
    struct haproxy_protocol_info *actual = *state;

    ALLOC_OBJ_CLEAR(expected, struct haproxy_protocol_info);

    /* v1 UNKNOWN protocol */
    assert_false(haproxy_protocol_parse(actual, HP1_TEST_UNKNOWN, sizeof(HP1_TEST_UNKNOWN)));

    /* v1 TCP4 */
    memset((actual), 0, sizeof(struct haproxy_protocol_info));
    haproxy_protocol_reset(actual);
    expected->version = HAPROXY_PROTOCOL_VERSION_1;
    expected->sock_type = SOCK_STREAM;
    expected->src.addr.sa.sa_family = AF_INET;
    expected->src.addr.in4.sin_addr.s_addr = htonl(0x0a0a1402);
    expected->src.addr.in4.sin_port = ntohs(40150);
    expected->dst.addr.sa.sa_family = AF_INET;
    expected->dst.addr.in4.sin_addr.s_addr = htonl(0x0a0a1401);
    expected->dst.addr.in4.sin_port = ntohs(1195);
    haproxy_protocol_parse(actual, HP1_TEST_TCP4, sizeof(HP1_TEST_TCP4));
    assert_true(compare_hpi(state, actual, expected));

    /* v1 TCP6 */
    haproxy_protocol_reset(actual);
    haproxy_protocol_reset(expected);
    memset((actual), 0, sizeof(struct haproxy_protocol_info));
    memset((expected), 0, sizeof(struct haproxy_protocol_info));
    expected->version = HAPROXY_PROTOCOL_VERSION_1;
    expected->sock_type = SOCK_STREAM;
    expected->src.addr.in6.sin6_family = AF_INET6;
    expected->src.addr.in6.sin6_port = ntohs(53344);
    inet_pton(AF_INET6, "2001:db8:20::2", &expected->src.addr.in6.sin6_addr);
    expected->dst.addr.in6.sin6_family = AF_INET6;
    expected->dst.addr.in6.sin6_port = ntohs(1195);
    inet_pton(AF_INET6, "2001:db8:20::1", &expected->dst.addr.in6.sin6_addr);
    haproxy_protocol_parse(actual, HP1_TEST_TCP6, sizeof(HP1_TEST_TCP6));
    assert_true(compare_hpi(state, actual, expected));

    /* v2 wrong version */
    haproxy_protocol_reset(actual);
    memset((actual), 0, sizeof(struct haproxy_protocol_info));
    assert_false(haproxy_protocol_parse(actual, HP2_TEST_WRONG_VER, sizeof(HP2_TEST_WRONG_VER)));

    /* v2 local */
    haproxy_protocol_reset(actual);
    memset((actual), 0, sizeof(struct haproxy_protocol_info));
    assert_false(haproxy_protocol_parse(actual, HP2_TEST_LOCAL, sizeof(HP2_TEST_LOCAL)));

    /* v2 TCP4 */
    haproxy_protocol_reset(actual);
    haproxy_protocol_reset(expected);
    memset((actual), 0, sizeof(struct haproxy_protocol_info));
    memset((expected), 0, sizeof(struct haproxy_protocol_info));
    expected->version = HAPROXY_PROTOCOL_VERSION_2;
    expected->sock_type = SOCK_STREAM;
    expected->src.addr.in4.sin_family = AF_INET;
    expected->src.addr.in4.sin_port = ntohs(42288);
    expected->src.addr.in4.sin_addr.s_addr = htonl(0x0a0a1402);
    expected->dst.addr.in4.sin_family = AF_INET;
    expected->dst.addr.in4.sin_port = ntohs(1195);
    expected->dst.addr.in4.sin_addr.s_addr = htonl(0x0a0a1401);
    haproxy_protocol_parse(actual, HP2_TEST_PROXY_TCP4, sizeof(HP2_TEST_PROXY_TCP4));
    assert_true(compare_hpi(state, actual, expected));

    /* v2 TCP6 */
    haproxy_protocol_reset(actual);
    haproxy_protocol_reset(expected);
    memset((actual), 0, sizeof(struct haproxy_protocol_info));
    memset((expected), 0, sizeof(struct haproxy_protocol_info));
    expected->version = HAPROXY_PROTOCOL_VERSION_2;
    expected->sock_type = SOCK_STREAM;
    expected->src.addr.in6.sin6_family = AF_INET6;
    expected->src.addr.in6.sin6_port = ntohs(59574);
    inet_pton(AF_INET6, "2001:db8:20::2", &expected->src.addr.in6.sin6_addr);
    expected->dst.addr.in6.sin6_family = AF_INET6;
    expected->dst.addr.in6.sin6_port = ntohs(1195);
    inet_pton(AF_INET6, "2001:db8:20::1", &expected->dst.addr.in6.sin6_addr);
    haproxy_protocol_parse(actual, HP2_TEST_PROXY_TCP6, sizeof(HP2_TEST_PROXY_TCP6));
    assert_true(compare_hpi(state, actual, expected));

    haproxy_protocol_reset(expected);
    free(expected);
}

int
main(void)
{
    openvpn_unit_test_setup();
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_haproxy_protocol_version),
        cmocka_unit_test(test_haproxy_protocol_header_len),
        cmocka_unit_test_setup_teardown(test_haproxy_protocol_parse, setup_parse, teardown_parse)
    };
    return cmocka_run_group_tests_name("haproxy_protocol", tests, NULL, NULL);
}
