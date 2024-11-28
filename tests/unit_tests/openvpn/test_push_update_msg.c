#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include "push.h"
#include "options_util.h"

/* mocks */

unsigned int
pull_permission_mask(const struct context *c)
{
    unsigned int flags =
        OPT_P_UP
        | OPT_P_ROUTE_EXTRAS
        | OPT_P_SOCKBUF
        | OPT_P_SOCKFLAGS
        | OPT_P_SETENV
        | OPT_P_SHAPER
        | OPT_P_TIMER
        | OPT_P_COMP
        | OPT_P_PERSIST
        | OPT_P_MESSAGES
        | OPT_P_EXPLICIT_NOTIFY
        | OPT_P_ECHO
        | OPT_P_PULL_MODE
        | OPT_P_PEER_ID
        | OPT_P_NCP
        | OPT_P_PUSH_MTU
        | OPT_P_ROUTE
        | OPT_P_DHCPDNS;
    return flags;
}

bool
apply_push_options(struct context *c,
                   struct options *options,
                   struct buffer *buf,
                   unsigned int permission_mask,
                   unsigned int *option_types_found,
                   struct env_set *es,
                   bool is_update)
{
    char line[OPTION_PARM_SIZE];

    while (buf_parse(buf, ',', line, sizeof(line)))
    {
        unsigned int push_update_option_flags = 0;

        if (!apply_pull_filter(options, line, is_update, &push_update_option_flags))
        {
            msg(M_WARN, "Offending option received from server");
            return false;
        }
        /*
         * No need to test also the application part here
         * (add_option/remove_option/update_option)
         */
    }
    return true;
}

int
process_incoming_push_msg(struct context *c,
                          const struct buffer *buffer,
                          bool honor_received_options,
                          unsigned int permission_mask,
                          unsigned int *option_types_found)
{
    struct buffer buf = *buffer;

    if (buf_string_compare_advance(&buf, "PUSH_REQUEST"))
    {
        return PUSH_MSG_REQUEST;
    }
    else if (honor_received_options
             && buf_string_compare_advance(&buf, push_reply_cmd))
    {
        return PUSH_MSG_REPLY;
    }
    else if (honor_received_options
             && buf_string_compare_advance(&buf, push_update_cmd))
    {
        return process_incoming_push_update(c, permission_mask,
                                            option_types_found, &buf);
    }
    else
    {
        return PUSH_MSG_ERROR;
    }
}

char **res;
int i;

bool send_control_channel_string(struct context *c, const char *str, int msglevel)
{
    if (res && res[i] && strcmp(res[i], str))
        return false;
    i++;
    return true;
}

/* tests */

static void
test_incoming_push_message_basic(void **state)
{
    struct context *c = *state;
    struct buffer buf = alloc_buf(256);
    const char *update_msg = "PUSH_UPDATE,dhcp-option DNS 8.8.8.8, route 0.0.0.0 0.0.0.0 10.10.10.1";
    buf_write(&buf, update_msg, strlen(update_msg));
    unsigned int option_types_found = 0;

    assert_int_equal(process_incoming_push_msg(c, &buf, c->options.pull, pull_permission_mask(c), &option_types_found), PUSH_MSG_UPDATE);

    free_buf(&buf);
}

static void
test_incoming_push_message_error1(void **state)
{
    struct context *c = *state;
    struct buffer buf = alloc_buf(256);
    const char *update_msg = "PUSH_UPDATEerr,dhcp-option DNS 8.8.8.8";
    buf_write(&buf, update_msg, strlen(update_msg));
    unsigned int option_types_found = 0;

    assert_int_equal(process_incoming_push_msg(c, &buf, c->options.pull, pull_permission_mask(c), &option_types_found), PUSH_MSG_ERROR);

    free_buf(&buf);
}


static void
test_incoming_push_message_error2(void **state)
{
    struct context *c = *state;
    struct buffer buf = alloc_buf(256);
    const char *update_msg = "PUSH_UPDATE ,dhcp-option DNS 8.8.8.8";
    buf_write(&buf, update_msg, strlen(update_msg));
    unsigned int option_types_found = 0;

    assert_int_equal(process_incoming_push_msg(c, &buf, c->options.pull, pull_permission_mask(c), &option_types_found), PUSH_MSG_ERROR);

    free_buf(&buf);
}

static void
test_incoming_push_message_1(void **state)
{
    struct context *c = *state;
    struct buffer buf = alloc_buf(256);
    const char *update_msg = "PUSH_UPDATE, -?dns, route something, ?dhcp-option DNS 8.8.8.8";
    buf_write(&buf, update_msg, strlen(update_msg));
    unsigned int option_types_found = 0;

    assert_int_equal(process_incoming_push_msg(c, &buf, c->options.pull, pull_permission_mask(c), &option_types_found), PUSH_MSG_UPDATE);

    free_buf(&buf);
}

static void
test_incoming_push_message_bad_format(void **state)
{
    struct context *c = *state;
    struct buffer buf = alloc_buf(256);
    const char *update_msg = "PUSH_UPDATE, -dhcp-option, ?-dns";
    buf_write(&buf, update_msg, strlen(update_msg));
    unsigned int option_types_found = 0;

    assert_int_equal(process_incoming_push_msg(c, &buf, c->options.pull, pull_permission_mask(c), &option_types_found), PUSH_MSG_ERROR);

    free_buf(&buf);
}

static void
test_incoming_push_message_not_updatable_option(void **state)
{
    struct context *c = *state;
    struct buffer buf = alloc_buf(256);
    const char *update_msg = "PUSH_UPDATE, dev tun";
    buf_write(&buf, update_msg, strlen(update_msg));
    unsigned int option_types_found = 0;

    assert_int_equal(process_incoming_push_msg(c, &buf, c->options.pull, pull_permission_mask(c), &option_types_found), PUSH_MSG_ERROR);

    free_buf(&buf);
}

static void
test_incoming_push_message_mix(void **state)
{
    struct context *c = *state;
    struct buffer buf = alloc_buf(256);
    const char *update_msg = "PUSH_UPDATE,-dhcp-option, route 10.10.10.0, dhcp-option DNS 1.1.1.1, route 10.11.12.0, dhcp-option DOMAIN corp.local, keepalive 10 60";
    buf_write(&buf, update_msg, strlen(update_msg));
    unsigned int option_types_found = 0;

    assert_int_equal(process_incoming_push_msg(c, &buf, c->options.pull, pull_permission_mask(c), &option_types_found), PUSH_MSG_UPDATE);

    free_buf(&buf);
}

static void
test_incoming_push_message_mix2(void **state)
{
    struct context *c = *state;
    struct buffer buf = alloc_buf(256);
    const char *update_msg = "PUSH_UPDATE,-dhcp-option,dhcp-option DNS 8.8.8.8,redirect-gateway local,route 192.168.1.0 255.255.255.0";
    buf_write(&buf, update_msg, strlen(update_msg));
    unsigned int option_types_found = 0;

    assert_int_equal(process_incoming_push_msg(c, &buf, c->options.pull, pull_permission_mask(c), &option_types_found), PUSH_MSG_UPDATE);

    free_buf(&buf);
}

char *r0[] = {
    "PUSH_UPDATE,redirect-gateway local,route 192.168.1.0 255.255.255.0"
};
char *r1[] = {
    "PUSH_UPDATE,-dhcp-option,blablalalalalalalalalalalalalf, lalalalalalalalalalalalalalaf,push-continuation 2",
    "PUSH_UPDATE, akakakakakakakakakakakaf, dhcp-option DNS 8.8.8.8,redirect-gateway local,push-continuation 2",
    "PUSH_UPDATE,route 192.168.1.0 255.255.255.0,push-continuation 1"
};
char *r3[] = {
    "PUSH_UPDATE,,,"
};
char *r4[] = {
    "PUSH_UPDATE,-dhcp-option, blablalalalalalalalalalalalalf, lalalalalalalalalalalalalalaf,push-continuation 2",
    "PUSH_UPDATE, akakakakakakakakakakakaf,dhcp-option DNS 8.8.8.8, redirect-gateway local,push-continuation 2",
    "PUSH_UPDATE, route 192.168.1.0 255.255.255.0,,push-continuation 1"
};
char *r5[] = {
    "PUSH_UPDATE,,-dhcp-option, blablalalalalalalalalalalalalf, lalalalalalalalalalalalalalaf,push-continuation 2",
    "PUSH_UPDATE, akakakakakakakakakakakaf,dhcp-option DNS 8.8.8.8, redirect-gateway local,push-continuation 2",
    "PUSH_UPDATE, route 192.168.1.0 255.255.255.0,push-continuation 1"
};
char *r6[] = {
    "PUSH_UPDATE,-dhcp-option,blablalalalalalalalalalalalalf, lalalalalalalalalalalalalalaf,push-continuation 2",
    "PUSH_UPDATE, akakakakakakakakakakakaf, dhcp-option DNS 8.8.8.8, redirect-gateway 10.10.10.10,,push-continuation 2",
    "PUSH_UPDATE, route 192.168.1.0 255.255.255.0,,push-continuation 1"
};
char *r7[] = {
    "PUSH_UPDATE,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,push-continuation 2",
    "PUSH_UPDATE,,,,,,,,,,,,,,,,,,,push-continuation 1"
};
char *r8[] = {
    "PUSH_UPDATE,-dhcp-option,blablalalalalalalalalalalalalf, lalalalalalalalalalalalalalaf,push-continuation 2",
    "PUSH_UPDATE, akakakakakakakakakakakaf, dhcp-option DNS 8.8.8.8,redirect-gateway\n local,push-continuation 2",
    "PUSH_UPDATE,route 192.168.1.0 255.255.255.0\n\n\n,push-continuation 1"
};
char *r9[] = {
    "PUSH_UPDATE,,"
};


const char *msg0 = "redirect-gateway local,route 192.168.1.0 255.255.255.0";
const char *msg1 = "-dhcp-option,blablalalalalalalalalalalalalf, lalalalalalalalalalalalalalaf, akakakakakakakakakakakaf, dhcp-option DNS 8.8.8.8,redirect-gateway local,route 192.168.1.0 255.255.255.0";
const char *msg2 = "";
const char *msg3 = ",,";
const char *msg4 = "-dhcp-option, blablalalalalalalalalalalalalf, lalalalalalalalalalalalalalaf, akakakakakakakakakakakaf,dhcp-option DNS 8.8.8.8, redirect-gateway local, route 192.168.1.0 255.255.255.0,";
const char *msg5 = ",-dhcp-option, blablalalalalalalalalalalalalf, lalalalalalalalalalalalalalaf, akakakakakakakakakakakaf,dhcp-option DNS 8.8.8.8, redirect-gateway local, route 192.168.1.0 255.255.255.0";
const char *msg6 = "-dhcp-option,blablalalalalalalalalalalalalf, lalalalalalalalalalalalalalaf, akakakakakakakakakakakaf, dhcp-option DNS 8.8.8.8, redirect-gateway 10.10.10.10,, route 192.168.1.0 255.255.255.0,";
const char *msg7 = ",,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,";
const char *msg8 = "-dhcp-option,blablalalalalalalalalalalalalf, lalalalalalalalalalalalalalaf, akakakakakakakakakakakaf, dhcp-option DNS 8.8.8.8,redirect-gateway\n local,route 192.168.1.0 255.255.255.0\n\n\n";
const char *msg9 = ",";
const char *msg10 = "Voilà! In view, a humble vaudevillian veteran cast vicariously as both victim and villain by the vicissitudes of Fate. This visage no mere veneer of vanity is a vestige of the vox populi now vacant vanished. However this valorous visitation of a by-gone vexation stands vivified and has vowed to vanquish these venal and virulent vermin vanguarding vice and vouchsafing the violently vicious and voracious violation of volition. The only verdict is vengeance; a vendetta held as a votive not in vain for the value and veracity of such shall one day vindicate the vigilant and the virtuous. Verily this vichyssoise of verbiage veers most verbose so let me simply add that it is my very good honor to meet you and you may call me V.";

static void test_send_push_msg0(void **state)
{
    i = 0;
    res = r0;
    struct context *c = *state;
    assert_true(send_push_update(c, msg0));
}
static void test_send_push_msg1(void **state)
{
    i = 0;
    res = r1;
    struct context *c = *state;
    assert_true(send_push_update(c, msg1));
}

static void test_send_push_msg2(void **state)
{
    i = 0;
    res = NULL;
    struct context *c = *state;
    assert_false(send_push_update(c, msg2));
}

static void test_send_push_msg3(void **state)
{
    i = 0;
    res = r3;
    struct context *c = *state;
    assert_true(send_push_update(c, msg3));
}

static void test_send_push_msg4(void **state)
{
    i = 0;
    res = r4;
    struct context *c = *state;
    assert_true(send_push_update(c, msg4));
}

static void test_send_push_msg5(void **state)
{
    i = 0;
    res = r5;
    struct context *c = *state;
    assert_true(send_push_update(c, msg5));
}

static void test_send_push_msg6(void **state)
{
    i = 0;
    res = r6;
    struct context *c = *state;
    assert_true(send_push_update(c, msg6));
}

static void test_send_push_msg7(void **state)
{
    i = 0;
    res = r7;
    struct context *c = *state;
    assert_true(send_push_update(c, msg7));
}

static void test_send_push_msg8(void **state)
{
    i = 0;
    res = r8;
    struct context *c = *state;
    assert_true(send_push_update(c, msg8));
}

static void test_send_push_msg9(void **state)
{
    i = 0;
    res = r9;
    struct context *c = *state;
    assert_true(send_push_update(c, msg9));
}

static void test_send_push_msg10(void **state)
{
    i = 0;
    res = NULL;
    struct context *c = *state;
    assert_false(send_push_update(c, msg10));
}

static int
setup(void **state)
{
    struct context *c = calloc(1, sizeof(struct context));
    c->options.pull = true;
    c->options.route_nopull = false;
    *state = c;
    return 0;
}

static int
teardown(void **state)
{
    struct context *c = *state;
    free(c);
    return 0;
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_incoming_push_message_basic, setup, teardown),
        cmocka_unit_test_setup_teardown(test_incoming_push_message_error1, setup, teardown),
        cmocka_unit_test_setup_teardown(test_incoming_push_message_error2, setup, teardown),
        cmocka_unit_test_setup_teardown(test_incoming_push_message_not_updatable_option, setup, teardown),
        cmocka_unit_test_setup_teardown(test_incoming_push_message_1, setup, teardown),
        cmocka_unit_test_setup_teardown(test_incoming_push_message_bad_format, setup, teardown),
        cmocka_unit_test_setup_teardown(test_incoming_push_message_mix, setup, teardown),
        cmocka_unit_test_setup_teardown(test_incoming_push_message_mix2, setup, teardown),
        cmocka_unit_test_setup_teardown(test_send_push_msg0, setup, teardown),
        cmocka_unit_test_setup_teardown(test_send_push_msg1, setup, teardown),
        cmocka_unit_test_setup_teardown(test_send_push_msg2, setup, teardown),
        cmocka_unit_test_setup_teardown(test_send_push_msg3, setup, teardown),
        cmocka_unit_test_setup_teardown(test_send_push_msg4, setup, teardown),
        cmocka_unit_test_setup_teardown(test_send_push_msg5, setup, teardown),
        cmocka_unit_test_setup_teardown(test_send_push_msg6, setup, teardown),
        cmocka_unit_test_setup_teardown(test_send_push_msg7, setup, teardown),
        cmocka_unit_test_setup_teardown(test_send_push_msg8, setup, teardown),
        cmocka_unit_test_setup_teardown(test_send_push_msg9, setup, teardown),
        cmocka_unit_test_setup_teardown(test_send_push_msg10, setup, teardown)
    };
    
    return cmocka_run_group_tests(tests, NULL, NULL);
}
