#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "push.h"
#include "multi.h"
#include "ssl_verify.h"

int
process_incoming_push_update(struct context *c,
                             unsigned int permission_mask,
                             unsigned int *option_types_found,
                             struct buffer *buf)
{
    int ret = PUSH_MSG_ERROR;
    const uint8_t ch = buf_read_u8(buf);
    if (ch == ',')
    {
        if (apply_push_options(c,
                               &c->options,
                               buf,
                               permission_mask,
                               option_types_found,
                               c->c2.es,
                               true))
        {
            switch (c->options.push_continuation)
            {
                case 0:
                case 1:
                    ret = PUSH_MSG_UPDATE;
                    break;

                case 2:
                    ret = PUSH_MSG_CONTINUATION;
                    break;
            }
        }
    }
    else if (ch == '\0')
    {
        ret = PUSH_MSG_UPDATE;
    }

    return ret;
}

/**
 * Return index of last `,` or `0` if it didn't find any.
 * If there is a comma at index `0` it's an error anyway
 */
static int
find_first_comma_of_next_bundle(const char *str, int ix)
{
    while (ix > 0)
    {
        if (str[ix] == ',')
        {
            return ix;
        }
        ix--;
    }
    return 0;
}

static char *
gc_strdup(const char *src, struct gc_arena *gc)
{
    char *ret = gc_malloc((strlen(src) + 1) * sizeof(char), true, gc);

    strcpy(ret, src);
    return ret;
}

/* It split the messagge (if necessay) and fill msgs with the message chunks.
 * Return `false` on failure an `true` on success.
 */
static bool
message_splitter(char *str, char **mesgs, struct gc_arena *gc, const int safe_cap)
{
    if (!str || !*str)
    {
        return false;
    }

    int i = 0;
    int im = 0;

    while (*str)
    {
        /* sizeof(push_update_cmd) + ',' - '/0' */
        if (strlen(str) + sizeof(push_update_cmd) > safe_cap)
        {
            int ci = find_first_comma_of_next_bundle(str, safe_cap - sizeof(push_update_cmd));
            if (!ci)
            {
                /* if no commas were found go to fail, do not send any message */
                return false;
            }
            str[ci] = '\0';
            /* copy from i to (ci -1) */
            mesgs[im] = gc_strdup(str, gc);
            i = ci + 1;
        }
        else
        {
            mesgs[im] = gc_strdup(str, gc);
            i = strlen(str);
        }
        str = &str[i];
        im++;
    }
    return true;
}

/* It actually send the already divided messagge to one single client */
static bool
send_single_push_update(struct context *c, char **msgs, struct buffer *buf, struct gc_arena *gc, const int push_bundle_size)
{
    if (!msgs[0] || !*msgs[0])
    {
        return false;
    }
    else if (!msgs[1] || !*msgs[1])
    {
        buf_printf(buf, "%s%c%s", push_update_cmd, ',', msgs[0]);
        if (!send_control_channel_string(c, BSTR(buf), D_PUSH))
        {
            return false;
        }
    }
    else
    {
        int i = 0;
        while (msgs[i] && *msgs[i])
        {
            if (msgs[i+1])
            {
                buf_printf(buf, "%s%c%s%s", push_update_cmd, ',', msgs[i], ",push-continuation 2");
            }
            else
            {
                buf_printf(buf, "%s%c%s%s", push_update_cmd, ',', msgs[i], ",push-continuation 1");
            }

            if (!send_control_channel_string(c, BSTR(buf), D_PUSH))
            {
                return false;
            }
            *buf = alloc_buf_gc(push_bundle_size, gc);
            i++;
        }
    }
    return true;
}

int
send_push_update(struct multi_context *m, const void *target, const char *msg, const push_update_type type, const int push_bundle_size)
{
    if (!msg || !*msg || !m
        || (!target && type != UPT_BROADCAST))
    {
        return -EINVAL;
    }

    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(push_bundle_size, &gc);
    /* extra space for possible trailing ifconfig and push-continuation */
    const int extra = 84;
    /* push_bundle_size is the maximum size of a message, so if the message
     * we want to send exceeds that size we have to split it into smaller messages */
    const int safe_cap = BCAP(&buf) - extra;
    int mexnum = (strlen(msg) / (safe_cap  - sizeof(push_update_cmd))) + 1;
    char **msgs = gc_malloc(sizeof(char *) * (mexnum + 1), true, &gc);

    msgs[mexnum] = NULL;
    if (!message_splitter(gc_strdup(msg, &gc), msgs, &gc, safe_cap))
    {
        gc_free(&gc);
        return -EINVAL;
    }

#ifdef ENABLE_MANAGEMENT
    if (type == UPT_BY_CID)
    {
        struct multi_instance *mi = lookup_by_cid(m, *((unsigned long *)target));

        if (!mi)
        {
            return -ENOENT;
        }
        if (!mi->halt
            && send_single_push_update(&mi->context, msgs, &buf, &gc, push_bundle_size))
        {
            gc_free(&gc);
            return 1;
        }
    }
#endif

    int count = 0;
    struct hash_iterator hi;
    const struct hash_element *he;

    hash_iterator_init(m->iter, &hi);
    while ((he = hash_iterator_next(&hi)))
    {
        struct multi_instance *curr_mi = he->value;

        if (curr_mi->halt)
        {
            continue;
        }
        if (type == UPT_BY_ADDR && !mroute_addr_equal(target, &curr_mi->real))
        {
            continue;
        }
        else if (type == UPT_BY_CN)
        {
            const char *curr_cn = tls_common_name(curr_mi->context.c2.tls_multi, false);
            if (strcmp(curr_cn, target))
            {
                continue;
            }
        }
        /* Either we found a matching client or type is UPT_BROADCAST so we update every client */
        if (!send_single_push_update(&curr_mi->context, msgs, &buf, &gc, push_bundle_size))
        {
            msg(M_CLIENT, "ERROR: Peer ID: %u has not been updated",
                curr_mi->context.c2.tls_multi ? curr_mi->context.c2.tls_multi->peer_id : UINT32_MAX);
            continue;
        }
        count++;
    }

    hash_iterator_free(&hi);
    gc_free(&gc);
    return count;
}

#ifdef ENABLE_MANAGEMENT
#define RETURN_UPDATE_STATUS(n_sent) \
    do { \
        if ((n_sent) > 0) { \
            msg(M_CLIENT, "SUCCESS: %d client(s) updated", (n_sent)); \
            return true; \
        } else { \
            msg(M_CLIENT, "ERROR: no client updated"); \
            return false; \
        } \
    } while (0)


bool
management_callback_send_push_update_broadcast(void *arg, const char *options)
{
    int n_sent = send_push_update(arg, NULL, options, UPT_BROADCAST, PUSH_BUNDLE_SIZE);

    RETURN_UPDATE_STATUS(n_sent);
}

bool
management_callback_send_push_update_by_cid(void *arg, unsigned long cid, const char *options)
{
    int ret = send_push_update(arg, &cid, options, UPT_BY_CID, PUSH_BUNDLE_SIZE);

    if (ret == -ENOENT)
    {
        msg(M_CLIENT, "ERROR: no client found with CID: %lu", cid);
    }

    return (ret > 0);
}

bool
management_callback_send_push_update_by_cn(void *arg, const char *cn, const char *options)
{
    int n_sent = send_push_update(arg, cn, options, UPT_BY_CN, PUSH_BUNDLE_SIZE);

    RETURN_UPDATE_STATUS(n_sent);
}

bool
management_callback_send_push_update_by_addr(void *arg, const struct mroute_addr *maddr, const char *options)
{
    int n_sent = send_push_update(arg, maddr, options, UPT_BY_ADDR, PUSH_BUNDLE_SIZE);

    RETURN_UPDATE_STATUS(n_sent);
}
#endif /* ifdef ENABLE_MANAGEMENT */
