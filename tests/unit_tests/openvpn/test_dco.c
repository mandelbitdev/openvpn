/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2026 OpenVPN Inc <sales@openvpn.net>
 *  Copyright (C) 2026 Gianmarco De Gregori <gianmarco@mandelbit.com>
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

/*
 *  Unit tests for the DCO capability queries.
 *
 *  Resolving a requirement is a single pass over a policy dump followed by a
 *  look at what the pass collected. The pass is fed dumps built by hand and
 *  the decision is fed a query filled in directly, which between them cover
 *  what would otherwise need a particular kernel.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"

#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

#include "dco_linux.c"

#define CMD_POLICY   4
#define SUB_POLICY   9
#define OTHER_POLICY 7

/* the bit is never read here, only the chain that would set it */
static const struct dco_capability_req test_req = { .cap = 1u,
                                                    .cmd = OVPN_CMD_PEER_NEW,
                                                    .nested_attr = OVPN_A_PEER,
                                                    .target_attr = OVPN_A_PEER_KEEPALIVE_INTERVAL,
                                                    .expected_type = NL_ATTR_TYPE_U32 };

/* the same requirement without a container: the target sits in the command's
 * own policy */
static const struct dco_capability_req flat_req = { .cap = 1u,
                                                    .cmd = OVPN_CMD_PEER_NEW,
                                                    .nested_attr = 0,
                                                    .target_attr = OVPN_A_IFINDEX,
                                                    .expected_type = NL_ATTR_TYPE_U32 };

static struct ovpn_cap_query
new_query_for(const struct dco_capability_req *req)
{
    struct ovpn_cap_query query = {
        .req = req, .cmd_policy = -1, .sub_policy = -1, .type = -1, .unclassified = 0
    };

    return query;
}

static struct ovpn_cap_query
new_query(void)
{
    return new_query_for(&test_req);
}

/* a CTRL_ATTR_OP_POLICY message saying which policy validates `cmd` */
static struct nl_msg *
msg_op_policy(uint16_t cmd, uint32_t do_policy)
{
    struct nl_msg *msg = nlmsg_alloc();
    struct nlattr *ops, *op;

    assert_non_null(msg);
    assert_non_null(genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, 0, 0, 0, CTRL_CMD_GETPOLICY, 0));

    ops = nla_nest_start(msg, CTRL_ATTR_OP_POLICY);
    op = nla_nest_start(msg, cmd);
    assert_int_equal(nla_put_u32(msg, CTRL_ATTR_POLICY_DO, do_policy), 0);
    nla_nest_end(msg, op);
    nla_nest_end(msg, ops);

    return msg;
}

/* one attribute of a policy: its id, which field of its descriptor to set,
 * and the value to put there */
struct attr_desc
{
    uint16_t attr_id;
    int field;
    uint32_t value;
};

/* a CTRL_ATTR_POLICY message describing `n` attributes of one policy */
static struct nl_msg *
msg_policy_attrs(uint32_t policy_id, const struct attr_desc *descs, size_t n)
{
    struct nl_msg *msg = nlmsg_alloc();
    struct nlattr *policies, *policy, *attr;

    assert_non_null(msg);
    assert_non_null(genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, 0, 0, 0, CTRL_CMD_GETPOLICY, 0));

    policies = nla_nest_start(msg, CTRL_ATTR_POLICY);
    policy = nla_nest_start(msg, policy_id);
    for (size_t i = 0; i < n; i++)
    {
        attr = nla_nest_start(msg, descs[i].attr_id);
        assert_int_equal(nla_put_u32(msg, descs[i].field, descs[i].value), 0);
        nla_nest_end(msg, attr);
    }
    nla_nest_end(msg, policy);
    nla_nest_end(msg, policies);

    return msg;
}

/* the shape the kernel actually sends: one attribute per message */
static struct nl_msg *
msg_policy_attr(uint32_t policy_id, uint16_t attr_id, int field, uint32_t value)
{
    const struct attr_desc one = { attr_id, field, value };

    return msg_policy_attrs(policy_id, &one, 1);
}

static void
feed(struct ovpn_cap_query *query, struct nl_msg *msg)
{
    assert_int_equal(ovpn_cap_query_cb(msg, query), NL_OK);
    nlmsg_free(msg);
}

/* Walk the whole chain, with both policies carrying attributes we are not
 * after and the ones we are neither first nor last, so that the pass has to
 * skip past them rather than stop at the first mismatch. */
static void
feed_full_chain(struct ovpn_cap_query *query)
{
    const struct attr_desc cmd_attrs[] = {
        { OVPN_A_IFINDEX, NL_POLICY_TYPE_ATTR_TYPE, NL_ATTR_TYPE_U32 },
        { OVPN_A_PEER, NL_POLICY_TYPE_ATTR_POLICY_IDX, SUB_POLICY },
        { OVPN_A_KEYCONF, NL_POLICY_TYPE_ATTR_TYPE, NL_ATTR_TYPE_NESTED },
    };
    const struct attr_desc sub_attrs[] = {
        { OVPN_A_PEER_ID, NL_POLICY_TYPE_ATTR_TYPE, NL_ATTR_TYPE_U32 },
        { OVPN_A_PEER_REMOTE_PORT, NL_POLICY_TYPE_ATTR_TYPE, NL_ATTR_TYPE_U16 },
        { test_req.target_attr, NL_POLICY_TYPE_ATTR_TYPE, NL_ATTR_TYPE_U32 },
        { OVPN_A_PEER_LOCAL_PORT, NL_POLICY_TYPE_ATTR_TYPE, NL_ATTR_TYPE_U16 },
    };

    feed(query, msg_op_policy(OVPN_CMD_PEER_NEW, CMD_POLICY));
    feed(query, msg_policy_attrs(CMD_POLICY, cmd_attrs, SIZE(cmd_attrs)));
    feed(query, msg_policy_attrs(SUB_POLICY, sub_attrs, SIZE(sub_attrs)));
}

/* the map tells us which policy validates the command we asked about */
static void
test_reads_command_policy(void **state)
{
    struct ovpn_cap_query query = new_query();

    feed(&query, msg_op_policy(OVPN_CMD_PEER_NEW, CMD_POLICY));
    assert_int_equal(query.cmd_policy, CMD_POLICY);
}

/* and not about another one, even though the dump is supposed to be filtered */
static void
test_ignores_other_command(void **state)
{
    struct ovpn_cap_query query = new_query();

    feed(&query, msg_op_policy(OVPN_CMD_PEER_DEL, CMD_POLICY));
    assert_int_equal(query.cmd_policy, -1);
}

/* the nested attribute of that policy points at the sub-policy */
static void
test_follows_nested_attribute(void **state)
{
    struct ovpn_cap_query query = new_query();

    feed(&query, msg_op_policy(OVPN_CMD_PEER_NEW, CMD_POLICY));
    feed(&query, msg_policy_attr(CMD_POLICY, OVPN_A_PEER, NL_POLICY_TYPE_ATTR_POLICY_IDX,
                                 SUB_POLICY));
    assert_int_equal(query.sub_policy, SUB_POLICY);
}

/* an attribute id only means something inside its own policy, so the same
 * number elsewhere says nothing about our question */
static void
test_ignores_nested_attribute_elsewhere(void **state)
{
    struct ovpn_cap_query query = new_query();

    feed(&query, msg_op_policy(OVPN_CMD_PEER_NEW, CMD_POLICY));
    feed(&query, msg_policy_attr(OTHER_POLICY, OVPN_A_PEER, NL_POLICY_TYPE_ATTR_POLICY_IDX,
                                 SUB_POLICY));
    assert_int_equal(query.sub_policy, -1);
}

/* the type of the target attribute is read in the sub-policy */
static void
test_reads_target_type(void **state)
{
    struct ovpn_cap_query query = new_query();

    feed_full_chain(&query);
    assert_int_equal(query.type, NL_ATTR_TYPE_U32);
}

/* and the same holds for the target attribute: a type read off some other
 * policy is not an answer to what we asked */
static void
test_ignores_target_attribute_elsewhere(void **state)
{
    struct ovpn_cap_query query = new_query();

    feed(&query, msg_op_policy(OVPN_CMD_PEER_NEW, CMD_POLICY));
    feed(&query, msg_policy_attr(CMD_POLICY, OVPN_A_PEER, NL_POLICY_TYPE_ATTR_POLICY_IDX,
                                 SUB_POLICY));
    feed(&query, msg_policy_attr(OTHER_POLICY, test_req.target_attr, NL_POLICY_TYPE_ATTR_TYPE,
                                 NL_ATTR_TYPE_U32));
    assert_int_equal(query.type, -1);
}

/* the command's own policy does get read, so the target attribute has to be
 * turned away there too: the same id there is a different attribute */
static void
test_ignores_target_attribute_in_command_policy(void **state)
{
    struct ovpn_cap_query query = new_query();

    feed(&query, msg_op_policy(OVPN_CMD_PEER_NEW, CMD_POLICY));
    feed(&query, msg_policy_attr(CMD_POLICY, OVPN_A_PEER, NL_POLICY_TYPE_ATTR_POLICY_IDX,
                                 SUB_POLICY));
    feed(&query, msg_policy_attr(CMD_POLICY, test_req.target_attr, NL_POLICY_TYPE_ATTR_TYPE,
                                 NL_ATTR_TYPE_U32));
    assert_int_equal(query.type, -1);
}

/* the sub-policy is read too, so the nested attribute has to be turned away
 * there as well */
static void
test_ignores_nested_attribute_in_sub_policy(void **state)
{
    struct ovpn_cap_query query = new_query();

    feed(&query, msg_op_policy(OVPN_CMD_PEER_NEW, CMD_POLICY));
    feed(&query, msg_policy_attr(CMD_POLICY, OVPN_A_PEER, NL_POLICY_TYPE_ATTR_POLICY_IDX,
                                 SUB_POLICY));
    feed(&query, msg_policy_attr(SUB_POLICY, OVPN_A_PEER, NL_POLICY_TYPE_ATTR_POLICY_IDX,
                                 OTHER_POLICY));
    assert_int_equal(query.sub_policy, SUB_POLICY);
}

/* an attribute that is there but not as a nest has nothing to follow */
static void
test_nested_attribute_without_policy_idx(void **state)
{
    struct ovpn_cap_query query = new_query();

    feed(&query, msg_op_policy(OVPN_CMD_PEER_NEW, CMD_POLICY));
    feed(&query, msg_policy_attr(CMD_POLICY, OVPN_A_PEER, NL_POLICY_TYPE_ATTR_TYPE,
                                 NL_ATTR_TYPE_U32));
    assert_int_equal(query.sub_policy, -1);
}

/* and one that is a nest says nothing about the type we are after */
static void
test_target_attribute_without_type(void **state)
{
    struct ovpn_cap_query query = new_query();

    feed(&query, msg_op_policy(OVPN_CMD_PEER_NEW, CMD_POLICY));
    feed(&query, msg_policy_attr(CMD_POLICY, OVPN_A_PEER, NL_POLICY_TYPE_ATTR_POLICY_IDX,
                                 SUB_POLICY));
    feed(&query, msg_policy_attr(SUB_POLICY, test_req.target_attr,
                                 NL_POLICY_TYPE_ATTR_POLICY_IDX, OTHER_POLICY));
    assert_int_equal(query.type, -1);
}

/* a policy we cannot place yet is counted, one we walk past afterwards is not */
static void
test_counts_only_what_it_could_not_place(void **state)
{
    struct ovpn_cap_query query = new_query();

    feed(&query, msg_op_policy(OVPN_CMD_PEER_NEW, CMD_POLICY));
    feed(&query, msg_policy_attr(OTHER_POLICY, OVPN_A_PEER_ID, NL_POLICY_TYPE_ATTR_TYPE,
                                 NL_ATTR_TYPE_U32));
    assert_int_equal(query.unclassified, 1);

    feed(&query, msg_policy_attr(CMD_POLICY, OVPN_A_PEER, NL_POLICY_TYPE_ATTR_POLICY_IDX,
                                 SUB_POLICY));
    feed(&query, msg_policy_attr(OTHER_POLICY, OVPN_A_PEER_ID, NL_POLICY_TYPE_ATTR_TYPE,
                                 NL_ATTR_TYPE_U32));
    assert_int_equal(query.unclassified, 1);
}

/* a flat requirement needs no hop: the command's policy is where to look */
static void
test_flat_requirement_reads_command_policy(void **state)
{
    struct ovpn_cap_query query = new_query_for(&flat_req);

    feed(&query, msg_op_policy(OVPN_CMD_PEER_NEW, CMD_POLICY));
    assert_int_equal(query.sub_policy, CMD_POLICY);

    feed(&query, msg_policy_attr(CMD_POLICY, flat_req.target_attr, NL_POLICY_TYPE_ATTR_TYPE,
                                 NL_ATTR_TYPE_U32));
    assert_int_equal(ovpn_cap_resolve(&query), OVPN_CAP_SUPPORTED);
}

/* and an absent one is a plain no, with nothing left unclassified */
static void
test_flat_requirement_absent_is_unsupported(void **state)
{
    struct ovpn_cap_query query = new_query_for(&flat_req);

    feed(&query, msg_op_policy(OVPN_CMD_PEER_NEW, CMD_POLICY));
    feed(&query, msg_policy_attr(OTHER_POLICY, flat_req.target_attr, NL_POLICY_TYPE_ATTR_TYPE,
                                 NL_ATTR_TYPE_U32));
    assert_int_equal(query.unclassified, 0);
    assert_int_equal(ovpn_cap_resolve(&query), OVPN_CAP_UNSUPPORTED);
}

/* nothing to read an answer out of is not the same as a "no" */
static void
test_resolve_without_command_policy(void **state)
{
    struct ovpn_cap_query query = new_query();

    assert_int_equal(ovpn_cap_resolve(&query), OVPN_CAP_UNKNOWN);
}

/* a kernel that does not nest the attribute simply never mentions it */
static void
test_resolve_nested_absent(void **state)
{
    struct ovpn_cap_query query = new_query();

    query.cmd_policy = CMD_POLICY;
    assert_int_equal(ovpn_cap_resolve(&query), OVPN_CAP_UNSUPPORTED);
}

/* unless the dump went by in an order we could not follow, in which case we
 * did not find out either way */
static void
test_resolve_incomplete_after_skipping(void **state)
{
    struct ovpn_cap_query query = new_query();

    query.cmd_policy = CMD_POLICY;
    query.unclassified = 1;
    assert_int_equal(ovpn_cap_resolve(&query), OVPN_CAP_UNKNOWN);
}

/* the sub-policy is there but does not define the attribute: the ordinary no */
static void
test_resolve_target_absent(void **state)
{
    struct ovpn_cap_query query = new_query();

    query.cmd_policy = CMD_POLICY;
    query.sub_policy = SUB_POLICY;
    assert_int_equal(ovpn_cap_resolve(&query), OVPN_CAP_UNSUPPORTED);
}

/* right name, wrong type: not the attribute we would be writing */
static void
test_resolve_wrong_type(void **state)
{
    struct ovpn_cap_query query = new_query();

    query.cmd_policy = CMD_POLICY;
    query.sub_policy = SUB_POLICY;
    query.type = NL_ATTR_TYPE_U8;
    assert_int_equal(ovpn_cap_resolve(&query), OVPN_CAP_UNSUPPORTED);
}

/* and the whole chain, from a dump to a yes */
static void
test_resolve_complete_chain(void **state)
{
    struct ovpn_cap_query query = new_query();

    feed_full_chain(&query);
    assert_int_equal(query.unclassified, 0);
    assert_int_equal(ovpn_cap_resolve(&query), OVPN_CAP_SUPPORTED);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_reads_command_policy),
        cmocka_unit_test(test_ignores_other_command),
        cmocka_unit_test(test_follows_nested_attribute),
        cmocka_unit_test(test_ignores_nested_attribute_elsewhere),
        cmocka_unit_test(test_reads_target_type),
        cmocka_unit_test(test_ignores_target_attribute_elsewhere),
        cmocka_unit_test(test_ignores_target_attribute_in_command_policy),
        cmocka_unit_test(test_ignores_nested_attribute_in_sub_policy),
        cmocka_unit_test(test_nested_attribute_without_policy_idx),
        cmocka_unit_test(test_target_attribute_without_type),
        cmocka_unit_test(test_counts_only_what_it_could_not_place),
        cmocka_unit_test(test_flat_requirement_reads_command_policy),
        cmocka_unit_test(test_flat_requirement_absent_is_unsupported),
        cmocka_unit_test(test_resolve_without_command_policy),
        cmocka_unit_test(test_resolve_nested_absent),
        cmocka_unit_test(test_resolve_incomplete_after_skipping),
        cmocka_unit_test(test_resolve_target_absent),
        cmocka_unit_test(test_resolve_wrong_type),
        cmocka_unit_test(test_resolve_complete_chain),
    };

    return cmocka_run_group_tests_name("dco", tests, NULL, NULL);
}
