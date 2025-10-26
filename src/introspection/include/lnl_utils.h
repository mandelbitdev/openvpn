#ifndef LNL_UTILS_H
#define LNL_UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include "ovpn_dco_linux.h"

#define GENL_MAX_FAM_OPS 0x100
#define GENL_MAX_FAM_GRPS 0x100

#define VALUE_NOT_SET -0x1

#define INITIAL_CAPACITY 0x1
#define EXPAND_RATIO 0x1

#define OVPN_PEER_NL_POLICY 0x3
#define OVPN_KEYCONF_NL_POLICY 0x4
#define OVPN_KEYDIR_NL_POLICY 0x5

struct netlink_ctx
{
    struct nl_sock *sock;
    struct nl_cb *cb;
};

struct Attr
{
    const char *attr_name;
    int nested_policy;
    int max_attr;
    const char *type;
    signed long long min_value_s;
    signed long long max_value_s;
    unsigned long long min_value_u;
    unsigned long long max_value_u;
    uint32_t min_len;
    uint32_t max_len;
};

struct ovpn_policy_info
{
    const char *cmd_name;
    struct Attr *attrs;
    size_t attr_count;
    size_t attr_capacity;
};

typedef struct
{
    int cmd;
    int doit;
    int dumpit;
} ovpn_policy_map_t;

ovpn_policy_map_t ovpn_policy_map[OVPN_CMD_MAX] = {
    { OVPN_CMD_NEW_IFACE, VALUE_NOT_SET, VALUE_NOT_SET },
    { OVPN_CMD_DEL_IFACE, VALUE_NOT_SET, VALUE_NOT_SET },
    { OVPN_CMD_SET_PEER, VALUE_NOT_SET, VALUE_NOT_SET },
    { OVPN_CMD_GET_PEER, VALUE_NOT_SET, VALUE_NOT_SET },
    { OVPN_CMD_DEL_PEER, VALUE_NOT_SET, VALUE_NOT_SET },
    { OVPN_CMD_SET_KEY, VALUE_NOT_SET, VALUE_NOT_SET },
    { OVPN_CMD_SWAP_KEYS, VALUE_NOT_SET, VALUE_NOT_SET },
    { OVPN_CMD_DEL_KEY, VALUE_NOT_SET, VALUE_NOT_SET },
};

static ovpn_policy_map_t *
get_op_by_policy(int policy_id)
{
    for (int i = 0; i < OVPN_CMD_MAX; i++)
    {
        if (ovpn_policy_map[i].doit == policy_id || ovpn_policy_map[i].dumpit == policy_id)
        {
            return &ovpn_policy_map[i];
        }
    }
    return NULL;
}

void
check_cmdln_args(int argc, char **argv, char **family_name)
{
    if (argc < 2)
    {
        perror("Netlink family name required");
        exit(EXIT_FAILURE);
    }
    *family_name = argv[1];
}

struct nl_sock *
create_netlink_socket()
{
    struct nl_sock *sock = nl_socket_alloc();
    if (!sock)
    {
        perror("nl_socket_alloc()");
        exit(EXIT_FAILURE);
    }

    nl_socket_disable_seq_check(sock);
    nl_socket_disable_auto_ack(sock);
    return sock;
}

struct nl_cb *
create_netlink_cb(int type)
{
    struct nl_cb *cb = nl_cb_alloc(type);
    if (!cb)
    {
        perror("Unable to allocate callback handler");
        exit(EXIT_FAILURE);
    }
    return cb;
}

struct nl_msg *
create_netlink_message(int family_id, unsigned int flags, int cmd)
{
    struct nl_msg *msg;
    msg = nlmsg_alloc();
    if (!msg)
    {
        perror("nlmsg_alloc()");
        return NULL;
    }

    if (!genlmsg_put(msg, 0, 0, family_id, 0, flags, cmd, 0))
    {
        perror("genlmsg_put()");
        nlmsg_free(msg);
        return NULL;
    }

    return msg;
}

void
send_netlink_message(struct nl_sock *sock, struct nl_msg *msg)
{
    int ret = nl_send_auto(sock, msg);
    if (ret < 0)
    {
        perror("nl_send_auto()");
        nlmsg_free(msg);
        nl_socket_free(sock);
        exit(EXIT_FAILURE);
    }
}

void
recv_netlink_message(struct nl_sock *sock, struct nl_cb *cb, struct nl_msg *msg)
{
    int ret = nl_recvmsgs(sock, cb);
    if (ret < 0)
    {
        fprintf(stderr, "nl_recvmsgs() error: %s\n", nl_geterror(ret));
        nl_cb_put(cb);
        nlmsg_free(msg);
        nl_socket_free(sock);
        exit(EXIT_FAILURE);
    }
}

int
get_family_id(struct nl_sock *sock, const char *family_name)
{
    int ret = genl_ctrl_resolve(sock, family_name);
    if (ret < 0)
    {
        fprintf(stderr, "Cannot find %s netlink component: %s\n", family_name, nl_geterror(ret));
    }
    return ret;
}

void
setup_ctx(struct netlink_ctx *ctx)
{
    int ret = genl_connect(ctx->sock);
    if (ret < 0)
    {
        perror("Unable to connect to generic netlink");
        exit(EXIT_FAILURE);
    }
}

struct netlink_ctx *
create_ctx()
{
    struct netlink_ctx *ctx;
    ctx = (struct netlink_ctx *)malloc(sizeof(struct netlink_ctx));
    if (!ctx)
    {
        perror("Cannot allocate netlink context");
        exit(EXIT_FAILURE);
    }
    ctx->sock = create_netlink_socket();
    setup_ctx(ctx);
    ctx->cb = create_netlink_cb(NL_CB_VALID);
    return ctx;
}


const char *
get_nla_type_str(unsigned int attr)
{
    switch (attr)
    {
#define C(x) case NL_ATTR_TYPE_ ## x: return #x
        C(U8);
        C(U16);
        C(U32);
        C(U64);
        C(STRING);
        C(FLAG);
        C(NESTED);
        C(NESTED_ARRAY);
        C(NUL_STRING);
        C(BINARY);
        C(S8);
        C(S16);
        C(S32);
        C(S64);
        C(BITFIELD32);

        default:
            return "unknown";
    }
}

static const char *
get_ovpn_cmd_name(uint32_t cmd_value)
{
    switch (cmd_value)
    {
        case OVPN_CMD_NEW_IFACE:
            return "OVPN_CMD_NEW_IFACE";

        case OVPN_CMD_DEL_IFACE:
            return "OVPN_CMD_DEL_IFACE";

        case OVPN_CMD_SET_PEER:
            return "OVPN_CMD_SET_PEER";

        case OVPN_CMD_GET_PEER:
            return "OVPN_CMD_GET_PEER";

        case OVPN_CMD_DEL_PEER:
            return "OVPN_CMD_DEL_PEER";

        case OVPN_CMD_SET_KEY:
            return "OVPN_CMD_SET_KEY";

        case OVPN_CMD_SWAP_KEYS:
            return "OVPN_CMD_SWAP_KEYS";

        case OVPN_CMD_DEL_KEY:
            return "OVPN_CMD_DEL_KEY";

        default:
            return NULL;
    }
}

static const char *
get_ovpn_attr_name(int cmd, int attr_value)
{
    switch (cmd)
    {
        case OVPN_CMD_NEW_IFACE:
        case OVPN_CMD_DEL_IFACE:
            switch (attr_value)
            {
                case OVPN_A_IFINDEX:
                    return "OVPN_A_IFINDEX";

                case OVPN_A_IFNAME:
                    return "OVPN_A_IFNAME";

                case OVPN_A_MODE:
                    return "OVPN_A_MODE";

                case OVPN_A_PEER:
                    return "OVPN_A_PEER";

                default:
                    return "UNKNOWN_ATTR";
            }
        case OVPN_CMD_GET_PEER:
        case OVPN_CMD_SET_PEER:
        case OVPN_CMD_DEL_PEER:
        case OVPN_CMD_SET_KEY:
        case OVPN_CMD_SWAP_KEYS:
        case OVPN_CMD_DEL_KEY:
            switch (attr_value)
            {
                case OVPN_A_IFINDEX:
                    return "OVPN_A_IFINDEX";
                default:
                    return "UNKWNOWN_ATTR";
            }
    }

    switch (attr_value)
    {
        case OVPN_A_KEYDIR_CIPHER_KEY:
            return "OVPN_A_KEYDIR_CIPHER_KEY";

        case OVPN_A_KEYDIR_NONCE_TAIL:
            return "OVPN_A_KEYDIR_NONCE_TAIL";

        default:
            return "UNKNOWN_ATTR";
    }
}

static const char *
get_nested_policies(int policy_id, int attr_value)
{
    switch (policy_id)
    {
        case OVPN_PEER_NL_POLICY:
            switch (attr_value)
            {
                case OVPN_A_PEER_ID:
                    return "OVPN_A_PEER_ID";

                case OVPN_A_PEER_SOCKADDR_REMOTE:
                    return "OVPN_A_PEER_SOCKADDR_REMOTE";

                case OVPN_A_PEER_SOCKET:
                    return "OVPN_A_PEER_SOCKET";

                case OVPN_A_PEER_VPN_IPV4:
                    return "OVPN_A_PEER_VPN_IPV4";

                case OVPN_A_PEER_VPN_IPV6:
                    return "OVPN_A_PEER_VPN_IPV6";

                case OVPN_A_PEER_LOCAL_IP:
                    return "OVPN_A_PEER_LOCAL_IP";

                case OVPN_A_PEER_LOCAL_PORT:
                    return "OVPN_A_PEER_LOCAL_PORT";

                case OVPN_A_PEER_KEEPALIVE_INTERVAL:
                    return "OVPN_A_PEER_KEEPALIVE_INTERVAL";

                case OVPN_A_PEER_KEEPALIVE_TIMEOUT:
                    return "OVPN_A_PEER_KEEPALIVE_TIMEOUT";

                case OVPN_A_PEER_DEL_REASON:
                    return "OVPN_A_PEER_DEL_REASON";

                case OVPN_A_PEER_KEYCONF:
                    return "OVPN_A_PEER_KEYCONF";

                case OVPN_A_PEER_VPN_RX_BYTES:
                    return "OVPN_A_PEER_VPN_RX_BYTES";

                case OVPN_A_PEER_VPN_TX_BYTES:
                    return "OVPN_A_PEER_VPN_TX_BYTES";

                case OVPN_A_PEER_VPN_RX_PACKETS:
                    return "OVPN_A_PEER_VPN_RX_PACKETS";

                case OVPN_A_PEER_VPN_TX_PACKETS:
                    return "OVPN_A_PEER_VPN_TX_PACKETS";

                case OVPN_A_PEER_LINK_RX_BYTES:
                    return "OVPN_A_PEER_LINK_RX_BYTES";

                case OVPN_A_PEER_LINK_TX_BYTES:
                    return "OVPN_A_PEER_LINK_TX_BYTES";

                case OVPN_A_PEER_LINK_RX_PACKETS:
                    return "OVPN_A_PEER_LINK_RX_PACKETS";

                case OVPN_A_PEER_LINK_TX_PACKETS:
                    return "OVPN_A_PEER_LINK_TX_PACKETS";

                default:
                    return "UNKNOWN ATTR";
            }

        case OVPN_KEYCONF_NL_POLICY:
            switch (attr_value)
            {
                case OVPN_A_KEYCONF_SLOT:
                    return "OVPN_A_KEYCONF_SLOT";

                case OVPN_A_KEYCONF_KEY_ID:
                    return "OVPN_A_KEYCONF_KEY_ID";

                case OVPN_A_KEYCONF_CIPHER_ALG:
                    return "OVPN_A_KEYCONF_CIPHER_ALG";

                case OVPN_A_KEYCONF_ENCRYPT_DIR:
                    return "OVPN_A_KEYCONF_ENCRYPT_DIR";

                case OVPN_A_KEYCONF_DECRYPT_DIR:
                    return "OVPN_A_KEYCONF_DECRYPT_DIR";

                default:
                    return "UNKNOWN ATTR";
            }

        case OVPN_KEYDIR_NL_POLICY:
            switch (attr_value)
            {
                case OVPN_A_KEYDIR_CIPHER_KEY:
                    return "OVPN_A_KEYDIR_CIPHER_KEY";

                case OVPN_A_KEYDIR_NONCE_TAIL:
                    return "OVPN_A_KEYDIR_NONCE_TAIL";

                default:
                    return "UNKNOWN ATTR";
            }

        default:
            return "NOT FOUND";
    }
}

static const char *get_root_attr(int policy_id, int attr)
{
    switch (policy_id)
    {
        case OVPN_PEER_NL_POLICY:
            switch (attr)
            {
                case OVPN_A_IFINDEX:
                    return "OVPN_A_IFINDEX";
                case OVPN_A_IFNAME:
                    return "OVPN_A_IFNAME";
                case OVPN_A_MODE:
                    return "OVPN_A_MODE";
                case OVPN_A_PEER:
                    return "OVPN_A_PEER";
                default:
                    return "UNKWOWN ATTR";
            }
        
        case OVPN_KEYCONF_NL_POLICY:
            switch (attr)
            {
                case OVPN_A_KEYCONF_SLOT:
                    return "OVPN_A_KEYCONF_SLOT";

                case OVPN_A_KEYCONF_KEY_ID:
                    return "OVPN_A_KEYCONF_KEY_ID";

                case OVPN_A_KEYCONF_CIPHER_ALG:
                    return "OVPN_A_KEYCONF_CIPHER_ALG";

                case OVPN_A_KEYCONF_ENCRYPT_DIR:
                    return "OVPN_A_KEYCONF_ENCRYPT_DIR";

                case OVPN_A_KEYCONF_DECRYPT_DIR:
                    return "OVPN_A_KEYCONF_DECRYPT_DIR";

                default:
                    return "UNKNOWN ATTR";
            }
        case OVPN_KEYDIR_NL_POLICY:
            switch (attr)
            {
                case OVPN_A_KEYDIR_CIPHER_KEY:
                    return "OVPN_A_KEYDIR_CIPHER_KEY";

                case OVPN_A_KEYDIR_NONCE_TAIL:
                    return "OVPN_A_KEYDIR_NONCE_TAIL";

                default:
                    return "UNKNOWN ATTR";
            }
        
        default:
            return "UNKNOWN_POLICY";
    }
}

static void
nl_get_policy(const struct nlattr *attr, struct ovpn_policy_info *infos)
{
    struct nlattr *pos;
    int rem;

    if (!infos)
    {
        infos = (struct ovpn_policy_info *)malloc(INITIAL_CAPACITY * sizeof(struct ovpn_policy_info));
        if (!infos)
        {
            perror("Error malloc");
            exit(1);
        }
        infos->attrs = NULL;
    }

    nla_for_each_nested(pos, attr, rem)
    {
        struct nlattr *nested;
        int nested_rem;
        uint32_t policy_id = nla_type(pos);
        const char *cmd_name = NULL;
        ovpn_policy_map_t *op_instance = NULL;

        op_instance = get_op_by_policy(policy_id);
        if (op_instance)
        {
            cmd_name = get_ovpn_cmd_name(op_instance->cmd);
            infos->cmd_name = cmd_name;
        }

        nla_for_each_nested(nested, pos, nested_rem)
        {
            const char *attr_name = NULL;
            uint32_t attr_value = nla_type(nested);
            if (!op_instance || !cmd_name)
            {
                attr_name = get_nested_policies(policy_id, attr_value);
            }
            else
            {
                attr_name = get_ovpn_attr_name(op_instance->cmd, attr_value);
            }

            //printf("Command: %s attr[%u]: attr_name=%s", cmd_name ? cmd_name : "nested policy", nla_type(nested), attr_name);

            if (!infos->attrs)
            {
                infos->attrs = (struct Attr *)malloc(INITIAL_CAPACITY * sizeof(struct Attr));
                if (!infos->attrs)
                {
                    perror("Error malloc");
                    exit(1);
                }
            }
            else
            {
                struct Attr *new_attrs = (struct Attr *)realloc(infos->attrs, EXPAND_RATIO * sizeof(struct Attr));
                if (!new_attrs)
                {
                    perror("Error realloc");
                    exit(1);
                }
                infos->attrs = new_attrs;
            }

            infos->attrs[infos->attr_count].attr_name = attr_name;
            infos->attrs[infos->attr_count].nested_policy = VALUE_NOT_SET;
            //printf("\nDebug attr_name: %s\n", infos->attrs[infos->attr_count].attr_name);

            struct nlattr *tp[NL_POLICY_TYPE_ATTR_MAX + 1] = {0};
            nla_parse_nested(tp, NL_POLICY_TYPE_ATTR_MAX, nested, NULL);

            if (tp[NL_POLICY_TYPE_ATTR_TYPE])
            {
                //printf(" type=%s", get_nla_type_str(nla_get_u32(tp[NL_POLICY_TYPE_ATTR_TYPE])));
                infos->attrs[infos->attr_count].type = get_nla_type_str(nla_get_u32(tp[NL_POLICY_TYPE_ATTR_TYPE]));
            }

            if (tp[NL_POLICY_TYPE_ATTR_POLICY_IDX])
            {
                //printf(" policy:%u", nla_get_u32(tp[NL_POLICY_TYPE_ATTR_POLICY_IDX]));
                infos->attrs[infos->attr_count].nested_policy = nla_get_u32(tp[NL_POLICY_TYPE_ATTR_POLICY_IDX]);
            }

            if (tp[NL_POLICY_TYPE_ATTR_POLICY_MAXTYPE])
            {
                //printf(" maxattr:%u", nla_get_u32(tp[NL_POLICY_TYPE_ATTR_POLICY_MAXTYPE]));
                infos->attrs[infos->attr_count].max_attr = nla_get_u32(tp[NL_POLICY_TYPE_ATTR_POLICY_MAXTYPE]);
            }

            if (tp[NL_POLICY_TYPE_ATTR_MIN_VALUE_S] && tp[NL_POLICY_TYPE_ATTR_MAX_VALUE_S])
            {
                infos->attrs[infos->attr_count].min_value_s = (signed long long)nla_get_u64(tp[NL_POLICY_TYPE_ATTR_MIN_VALUE_S]);
                infos->attrs[infos->attr_count].max_value_s = (signed long long)nla_get_u64(tp[NL_POLICY_TYPE_ATTR_MAX_VALUE_S]);
                /*printf(" range:[%lld,%lld]",
                       (signed long long)nla_get_u64(tp[NL_POLICY_TYPE_ATTR_MIN_VALUE_S]),
                       (signed long long)nla_get_u64(tp[NL_POLICY_TYPE_ATTR_MAX_VALUE_S]));*/
            }

            if (tp[NL_POLICY_TYPE_ATTR_MIN_VALUE_U] && tp[NL_POLICY_TYPE_ATTR_MAX_VALUE_U])
            {
                infos->attrs[infos->attr_count].min_value_u = (unsigned long long)nla_get_u64(tp[NL_POLICY_TYPE_ATTR_MIN_VALUE_U]);
                infos->attrs[infos->attr_count].max_value_u = (unsigned long long)nla_get_u64(tp[NL_POLICY_TYPE_ATTR_MAX_VALUE_U]);
                /*printf(" range:[%llu,%llu]",
                       (unsigned long long)nla_get_u64(tp[NL_POLICY_TYPE_ATTR_MIN_VALUE_U]),
                       (unsigned long long)nla_get_u64(tp[NL_POLICY_TYPE_ATTR_MAX_VALUE_U]));*/
            }

            if (tp[NL_POLICY_TYPE_ATTR_MIN_LENGTH])
            {
                infos->attrs[infos->attr_count].min_len = nla_get_u32(tp[NL_POLICY_TYPE_ATTR_MIN_LENGTH]);
                //printf(" min len:%u", nla_get_u32(tp[NL_POLICY_TYPE_ATTR_MIN_LENGTH]));
            }

            if (tp[NL_POLICY_TYPE_ATTR_MAX_LENGTH])
            {
                infos->attrs[infos->attr_count].max_len = nla_get_u32(tp[NL_POLICY_TYPE_ATTR_MAX_LENGTH]);
                //printf(" max len:%u", nla_get_u32(tp[NL_POLICY_TYPE_ATTR_MAX_LENGTH]));
            }

            if (infos->attrs[infos->attr_count].nested_policy != VALUE_NOT_SET && infos->cmd_name != NULL)
            {
                //if (strcmp(infos->attrs[infos->attr_count].attr_name, attr_name) != 0)
                    infos->attrs[infos->attr_count].attr_name = get_root_attr(infos->attrs[infos->attr_count].nested_policy, attr_value);
            }

            /* DEBUG */
            if (infos->cmd_name != NULL)
            {   
                printf("\n"); 
                printf("cmd: <%s> ", infos->cmd_name);
                printf("Attr_name: %s ", infos->attrs[infos->attr_count].attr_name);
                if (infos->attrs[infos->attr_count].nested_policy != VALUE_NOT_SET)
                {
                    printf("Nested policy: %d ", infos->attrs[infos->attr_count].nested_policy);
                }
                printf("max_attr: %d ", infos->attrs[infos->attr_count].max_attr);
                printf("type: %s ", infos->attrs[infos->attr_count].type);
                printf("\n");
            }
        }
    }
}

static void
nl_print_policy(const struct nlattr *attr, FILE *fp)
{
    struct nlattr *pos;
    int rem;
    nla_for_each_nested(pos, attr, rem)
    {
        struct nlattr *nested;
        int nested_rem;

        fprintf(fp, " policy[%u]:", nla_type(pos));

        nla_for_each_nested(nested, pos, nested_rem)
        {
            struct nlattr *tp[NL_POLICY_TYPE_ATTR_MAX + 1] = {0};
            nla_parse_nested(tp, NL_POLICY_TYPE_ATTR_MAX, nested, NULL);

            if (tp[NL_POLICY_TYPE_ATTR_TYPE])
            {
                fprintf(fp, " attr[%u]: type=%s",
                        nla_type(nested),
                        get_nla_type_str(nla_get_u32(tp[NL_POLICY_TYPE_ATTR_TYPE])));
            }

            if (tp[NL_POLICY_TYPE_ATTR_POLICY_IDX])
            {
                fprintf(fp, " policy:%u",
                        nla_get_u32(tp[NL_POLICY_TYPE_ATTR_POLICY_IDX]));
            }

            if (tp[NL_POLICY_TYPE_ATTR_POLICY_MAXTYPE])
            {
                fprintf(fp, " maxattr:%u",
                        nla_get_u32(tp[NL_POLICY_TYPE_ATTR_POLICY_MAXTYPE]));
            }

            if (tp[NL_POLICY_TYPE_ATTR_MIN_VALUE_S] && tp[NL_POLICY_TYPE_ATTR_MAX_VALUE_S])
            {
                fprintf(fp, " range:[%lld,%lld]",
                        (signed long long)nla_get_u64(tp[NL_POLICY_TYPE_ATTR_MIN_VALUE_S]),
                        (signed long long)nla_get_u64(tp[NL_POLICY_TYPE_ATTR_MAX_VALUE_S]));
            }

            if (tp[NL_POLICY_TYPE_ATTR_MIN_VALUE_U] && tp[NL_POLICY_TYPE_ATTR_MAX_VALUE_U])
            {
                fprintf(fp, " range:[%llu,%llu]",
                        (unsigned long long)nla_get_u64(tp[NL_POLICY_TYPE_ATTR_MIN_VALUE_U]),
                        (unsigned long long)nla_get_u64(tp[NL_POLICY_TYPE_ATTR_MAX_VALUE_U]));
            }

            if (tp[NL_POLICY_TYPE_ATTR_MIN_LENGTH])
            {
                fprintf(fp, " min len:%u",
                        nla_get_u32(tp[NL_POLICY_TYPE_ATTR_MIN_LENGTH]));
            }

            if (tp[NL_POLICY_TYPE_ATTR_MAX_LENGTH])
            {
                fprintf(fp, " max len:%u",
                        nla_get_u32(tp[NL_POLICY_TYPE_ATTR_MAX_LENGTH]));
            }
        }
    }
}

static int
print_ctrl_grp(FILE *fp, struct nlattr *arg)
{
    struct nlattr *tb[CTRL_ATTR_MCAST_GRP_MAX + 1] = {0};

    if (arg == NULL)
    {
        return -1;
    }

    nla_parse_nested(tb, CTRL_ATTR_MCAST_GRP_MAX, arg, NULL);

    if (tb[CTRL_ATTR_MCAST_GRP_ID])
    {
        __u32 id = nla_get_u32(tb[CTRL_ATTR_MCAST_GRP_ID]);
        fprintf(fp, " ID-0x%x ", id);
    }
    if (tb[CTRL_ATTR_MCAST_GRP_NAME])
    {
        char *name = nla_get_string(tb[CTRL_ATTR_MCAST_GRP_NAME]);
        fprintf(fp, " name: %s ", name);
    }
    return 0;
}

static void
print_ctrl_cmd_flags(FILE *fp, unsigned int fl)
{
    fprintf(fp, "\n\t\tCapabilities (0x%x):\n ", fl);
    if (!fl)
    {
        fprintf(fp, "\n");
        return;
    }
    fprintf(fp, "\t\t ");

    if (fl & GENL_ADMIN_PERM)
    {
        fprintf(fp, " requires admin permission;");
    }
    if (fl & GENL_CMD_CAP_DO)
    {
        fprintf(fp, " can doit;");
    }
    if (fl & GENL_CMD_CAP_DUMP)
    {
        fprintf(fp, " can dumpit;");
    }
    if (fl & GENL_CMD_CAP_HASPOL)
    {
        fprintf(fp, " has policy");
    }

    fprintf(fp, "\n");
}

static int
print_ctrl_cmds(FILE *fp, struct nlattr *arg)
{
    struct nlattr *tb[CTRL_ATTR_OP_MAX + 1] = {0};

    if (arg == NULL)
    {
        return -1;
    }

    nla_parse_nested(tb, CTRL_ATTR_OP_MAX, arg, NULL);

    if (tb[CTRL_ATTR_OP_ID])
    {
        __u32 id = nla_get_u32(tb[CTRL_ATTR_OP_ID]);
        fprintf(fp, " ID-0x%x ", id);
    }

    if (tb[CTRL_ATTR_OP_FLAGS])
    {
        __u32 fl = nla_get_u32(tb[CTRL_ATTR_OP_FLAGS]);
        print_ctrl_cmd_flags(fp, fl);
    }

    return 0;
}

#endif /* ifndef LNL_UTILS_H */
