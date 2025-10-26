#ifndef LNL_CALLBACKS_H
#define LNL_CALLBACKS_H

#include "lnl_utils.h"

int
defined_op_dump_cb(struct nl_msg *msg, void *arg __attribute__((unused)))
{
    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    struct genlmsghdr *gnlh = (struct genlmsghdr *)nlmsg_data(nlh);
    struct nlattr *tb[CTRL_ATTR_MAX + 1];
    int len = nlh->nlmsg_len;
    struct nlattr *attrs;
    struct ovpn_policy_info *ovpn_policy_infos = NULL;

    if (nlh->nlmsg_type != GENL_ID_CTRL)
    {
        fprintf(stderr, "Not a controller message, nlmsg_len=%d nlmsg_type=0x%x\n", nlh->nlmsg_len, nlh->nlmsg_type);
        return 0;
    }

    if (gnlh->cmd != CTRL_CMD_GETFAMILY
        && gnlh->cmd != CTRL_CMD_DELFAMILY
        && gnlh->cmd != CTRL_CMD_NEWFAMILY
        && gnlh->cmd != CTRL_CMD_NEWMCAST_GRP
        && gnlh->cmd != CTRL_CMD_DELMCAST_GRP
        && gnlh->cmd != CTRL_CMD_GETPOLICY)
    {
        fprintf(stderr, "Unknown controller command %d\n", gnlh->cmd);
        return 0;
    }

    len -= NLMSG_LENGTH(GENL_HDRLEN);

    attrs = (struct nlattr *)((char *)gnlh + GENL_HDRLEN);
    nla_parse(tb, CTRL_ATTR_MAX, attrs, len, NULL);

    if (tb[CTRL_ATTR_OP_POLICY])
    {
        struct nlattr *pos;
        int rem;

        nla_for_each_nested(pos, tb[CTRL_ATTR_OP_POLICY], rem)
        {
            struct nlattr *ptb[CTRL_ATTR_POLICY_DUMP_MAX + 1];
            struct nlattr *pattrs = nla_data(pos);
            int plen = nla_len(pos);

            nla_parse(ptb, CTRL_ATTR_POLICY_DUMP_MAX, pattrs, plen, NULL);

            if (ptb[CTRL_ATTR_POLICY_DO])
            {
                __u32 v = nla_get_u32(ptb[CTRL_ATTR_POLICY_DO]);
                ovpn_policy_map[nla_type(pos) - 1].doit = v;
            }

            if (ptb[CTRL_ATTR_POLICY_DUMP])
            {
                __u32 v = nla_get_u32(ptb[CTRL_ATTR_POLICY_DUMP]);
                ovpn_policy_map[nla_type(pos) - 1].dumpit = v;
            }

            printf("\nCMD: <%s>, do: %d, dump: %d\n", get_ovpn_cmd_name(ovpn_policy_map[nla_type(pos) - 1].cmd), ovpn_policy_map[nla_type(pos) - 1].doit, (ovpn_policy_map[nla_type(pos) - 1].dumpit != VALUE_NOT_SET ? ovpn_policy_map[nla_type(pos) - 1].dumpit : -1));
        }
    }
    if (tb[CTRL_ATTR_POLICY])
    {
        nl_get_policy(tb[CTRL_ATTR_POLICY], ovpn_policy_infos);
    }
    return 0;
}

int
op_dump_cb(struct nl_msg *msg, void *arg __attribute__((unused)))
{
    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    struct genlmsghdr *gnlh = (struct genlmsghdr *)nlmsg_data(nlh);
    struct nlattr *tb[CTRL_ATTR_MAX + 1];
    int len = nlh->nlmsg_len;
    struct nlattr *attrs;
    FILE *fp = stdout;

    if (nlh->nlmsg_type !=  GENL_ID_CTRL)
    {
        fprintf(stderr, "Not a controller message, nlmsg_len=%d "
                "nlmsg_type=0x%x\n", nlh->nlmsg_len, nlh->nlmsg_type);
        return 0;
    }

    if (gnlh->cmd != CTRL_CMD_GETFAMILY
        && gnlh->cmd != CTRL_CMD_DELFAMILY
        && gnlh->cmd != CTRL_CMD_NEWFAMILY
        && gnlh->cmd != CTRL_CMD_NEWMCAST_GRP
        && gnlh->cmd != CTRL_CMD_DELMCAST_GRP
        && gnlh->cmd != CTRL_CMD_GETPOLICY)
    {
        fprintf(stderr, "Unknown controller command %d\n", gnlh->cmd);
        return 0;
    }

    len -= NLMSG_LENGTH(GENL_HDRLEN);

    if (len < 0)
    {
        fprintf(stderr, "wrong controller message len %d\n", len);
        return -1;
    }

    attrs = (struct nlattr *) ((char *) gnlh + GENL_HDRLEN);
    nla_parse(tb, CTRL_ATTR_MAX, attrs, len, NULL);

    if (tb[CTRL_ATTR_FAMILY_NAME])
    {
        char *name = nla_get_string(tb[CTRL_ATTR_FAMILY_NAME]);
        fprintf(fp, "\nName: %s\n", name);
    }
    if (tb[CTRL_ATTR_FAMILY_ID])
    {
        __u16 id = nla_get_u16(tb[CTRL_ATTR_FAMILY_ID]);
        fprintf(fp, "\tID: 0x%x ", id);
    }
    if (tb[CTRL_ATTR_VERSION])
    {
        __u32 v = nla_get_u32(tb[CTRL_ATTR_VERSION]);
        fprintf(fp, " Version: 0x%x ", v);
    }
    if (tb[CTRL_ATTR_HDRSIZE])
    {
        __u32 h = nla_get_u32(tb[CTRL_ATTR_HDRSIZE]);
        fprintf(fp, " header size: %d ", h);
    }
    if (tb[CTRL_ATTR_MAXATTR])
    {
        __u32 ma = nla_get_u32(tb[CTRL_ATTR_MAXATTR]);
        fprintf(fp, " max attribs: %d ", ma);
    }
    if (tb[CTRL_ATTR_OP_POLICY])
    {
        struct nlattr *pos;
        int rem;
        nla_for_each_nested(pos, tb[CTRL_ATTR_OP_POLICY], rem)
        {
            struct nlattr *ptb[CTRL_ATTR_POLICY_DUMP_MAX + 1];
            struct nlattr *pattrs = nla_data(pos);
            int plen = nla_len(pos);

            nla_parse(ptb, CTRL_ATTR_POLICY_DUMP_MAX, pattrs, plen, NULL);

            fprintf(fp, " op %d policies:", nla_type(pos));

            if (ptb[CTRL_ATTR_POLICY_DO])
            {
                __u32 v = nla_get_u32(ptb[CTRL_ATTR_POLICY_DO]);
                fprintf(fp, " do=%d", v);
            }

            if (ptb[CTRL_ATTR_POLICY_DUMP])
            {
                __u32 v = nla_get_u32(ptb[CTRL_ATTR_POLICY_DUMP]);
                fprintf(fp, " dump=%d", v);
            }
            fprintf(fp, "\n");
            return NL_OK;
        }
    }
    if (tb[CTRL_ATTR_POLICY])
    {
        nl_print_policy(tb[CTRL_ATTR_POLICY], fp);
    }

    fprintf(fp, "\n");
    if (tb[CTRL_ATTR_OPS])
    {
        struct nlattr *tb2[GENL_MAX_FAM_OPS + 1];
        int i = 0;
        nla_parse_nested(tb2, GENL_MAX_FAM_OPS, tb[CTRL_ATTR_OPS], NULL);
        fprintf(fp, "\tcommands supported: \n");
        for (i = 0; i < GENL_MAX_FAM_OPS; i++)
        {
            if (tb2[i])
            {
                fprintf(fp, "\t\t#%d: ", i);
                if (0 > print_ctrl_cmds(fp, tb2[i]))
                {
                    fprintf(fp, "Error printing command\n");
                }
                fprintf(fp, "\n");
            }
        }
        fprintf(fp, "\n");
    }

    if (tb[CTRL_ATTR_MCAST_GROUPS])
    {
        struct nlattr *tb2[GENL_MAX_FAM_GRPS + 1];
        int i;

        nla_parse_nested(tb2, GENL_MAX_FAM_GRPS, tb[CTRL_ATTR_MCAST_GROUPS], NULL);
        fprintf(fp, "\tmulticast groups:\n");

        for (i = 0; i < GENL_MAX_FAM_GRPS; i++)
        {
            if (tb2[i])
            {
                fprintf(fp, "\t\t#%d: ", i);
                if (0 > print_ctrl_grp(fp, tb2[i]))
                {
                    fprintf(fp, "Error printing group\n");
                }
                fprintf(fp, "\n");
            }
        }
        fprintf(fp, "\n");
    }

    fflush(fp);
    return 0;
}

#endif /* ifndef LNL_CALLBACKS_H */
