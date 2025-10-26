#include "../include/lnl_callbacks.h"

int
main(int argc, char **argv)
{
    struct netlink_ctx *ctx;
    struct nl_msg *msg;
    char *family_name = NULL;

    check_cmdln_args(argc, argv, &family_name);
    ctx = create_ctx();

    msg = create_netlink_message(GENL_ID_CTRL, NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST, CTRL_CMD_GETPOLICY);
    nla_put_string(msg, CTRL_ATTR_FAMILY_NAME, family_name);

    send_netlink_message(ctx->sock, msg);
    nl_cb_set(ctx->cb, NL_CB_VALID, NL_CB_CUSTOM, defined_op_dump_cb, NULL);
    recv_netlink_message(ctx->sock, ctx->cb, msg);

    nl_cb_put(ctx->cb);
    nlmsg_free(msg);
    nl_socket_free(ctx->sock);
    free(ctx);
    exit(EXIT_SUCCESS);
}
