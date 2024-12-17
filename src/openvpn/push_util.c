#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "push.h"
#include "multi.h"
#include "ssl_verify.h"

#define UPT_BY_ADDR (1<<0)
#define UPT_BY_CN   (1<<1)

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
 Return index of last `,` or `0` if it didn't find any.
 If there is a comma at index `0` it's an error anyway
 */
static int find_first_comma_of_next_bundle(const char *str, int ix)
{
    while (ix > 0)
    {
        if (str[ix] == ',')
            return ix;
        ix--;
    }
    return 0;
}

static char * gc_strdup(const char *src, struct gc_arena *gc)
{
    char * ret = gc_malloc((strlen(src) + 1) * sizeof(char), true, gc);
    strcpy(ret, src);
    return ret;
}

static bool message_splitter(char *str, char **mexs, struct gc_arena *gc, const int safe_cap)
{
    if (!str || !*str)
        return false;
    int i = 0;
    int im = 0;
    while (*str)
    {
        if (strlen(str) + sizeof(push_update_cmd) > safe_cap)/* sizeof(push_update_cmd) + ',' - '/0' */
        {
            int ci = find_first_comma_of_next_bundle(str, safe_cap - sizeof(push_update_cmd));
            if (!ci)
               return false;/* if no commas were found go to fail, do not send any message */
            
            str[ci] = '\0';
            mexs[im] = gc_strdup(str, gc);/* copy from i to (ci -1) */
            i = ci + 1; 
        }
        else
        {
            mexs[im] = gc_strdup(str, gc);
            i = strlen(str);
        }
        str = &str[i];
        im++;
    }
    return true;
}

static bool
send_single_push_update(struct context *c, char **mexs, struct buffer *buf, struct gc_arena *gc, const int push_bundle_size)
{
    if (!mexs[0] || !*mexs[0])
    {
        return false;
    }
    else if (!mexs[1] || !*mexs[1])
    {
        buf_printf(buf, "%s%c%s", push_update_cmd, ',', mexs[0]);
        const bool status = send_control_channel_string(c, BSTR(buf), D_PUSH);
        if (!status)
            return false;
    }
    else
    {
        int i = 0;
        while(mexs[i] && *mexs[i])
        {
            if (mexs[i+1])
                buf_printf(buf, "%s%c%s%s", push_update_cmd, ',', mexs[i], ",push-continuation 2");
            else
                buf_printf(buf, "%s%c%s%s", push_update_cmd, ',', mexs[i], ",push-continuation 1");

            const bool status = send_control_channel_string(c, BSTR(buf), D_PUSH);
            if (!status)
            {
                *buf = alloc_buf_gc(push_bundle_size, gc);
                buf_printf(buf, "%s%s", push_update_cmd, ",push-continuation 1");
                send_control_channel_string(c, BSTR(buf), D_PUSH);///should i?
                return false;
            }
            *buf = alloc_buf_gc(push_bundle_size, gc);
            i++;
        }
    }
    return true;
}

#define SEND_PUSH_UPDATE(curr_mi, mexs, buf, gc, push_bundle_size, count) \
    do { \
        if (!send_single_push_update(&(curr_mi)->context, (mexs), (buf), (gc), (push_bundle_size))) \
            msg(M_CLIENT, "ERROR: Peer ID: %u has not been updated", \
                (curr_mi)->context.c2.tls_multi ? (curr_mi)->context.c2.tls_multi->peer_id : UINT32_MAX); \
        else \
            (count)++; \
    } while (0)

static int
send_push_update(struct multi_context *m, struct multi_instance *mi, const char *mex, const int mode, const int push_bundle_size)
{
    if (!mex || !*mex || (!m && !mi))
        return -1;
    const int extra = 84; /* extra space for possible trailing ifconfig and push-continuation */
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(push_bundle_size, &gc);
    const int safe_cap = BCAP(&buf) - extra;
    int mexnum = (strlen(mex) / (safe_cap  - sizeof(push_update_cmd))) + 1;
    char **mexs = gc_malloc(sizeof(char *) * (mexnum + 1), true, &gc);
    mexs[mexnum] = NULL;
    int count = 0;

    
    if (!message_splitter(gc_strdup(mex, &gc), mexs, &gc, safe_cap))
    {
        gc_free(&gc);
        return -1;
    }

    if (m)
    {
        struct hash_iterator hi;
        const struct hash_element *he;
        hash_iterator_init(m->iter, &hi);
        
        if (!mi)/* broadcast */
        {
            while ((he = hash_iterator_next(&hi)))
            {
                struct multi_instance *curr_mi = (struct multi_instance *) he->value;

                if (!curr_mi->halt)
                {
                    SEND_PUSH_UPDATE(curr_mi, mexs, &buf, &gc, push_bundle_size, count);
                }
            }
        }
        else if (mode & UPT_BY_CN)/* common name multicast */
        {
            /// OPTIMIZATION(?): find position of mi in it and start from there
            const char *cn = tls_common_name(mi->context.c2.tls_multi, false);
            while ((he = hash_iterator_next(&hi)))
            {
                struct multi_instance *curr_mi = (struct multi_instance *) he->value;
                const char *curr_cn = tls_common_name(curr_mi->context.c2.tls_multi, false);

                if (!curr_mi->halt && curr_cn && streq(cn, curr_cn))
                {
                    SEND_PUSH_UPDATE(curr_mi, mexs, &buf, &gc, push_bundle_size, count);
                }
            }
        }
        else if (mode & UPT_BY_ADDR)/* address multicast */
        {
            /// OPTIMIZATION(?)
            struct mroute_addr *maddr = &mi->real;
            while ((he = hash_iterator_next(&hi)))
            {
                struct multi_instance *curr_mi = (struct multi_instance *) he->value;
                if (!mi->halt && maddr && mroute_addr_equal(maddr, &curr_mi->real))
                {
                    SEND_PUSH_UPDATE(curr_mi, mexs, &buf, &gc, push_bundle_size, count);
                }
            }
        }
        hash_iterator_free(&hi);
    }
    else if (!mi->halt &&
             send_single_push_update(&mi->context, mexs, &buf, &gc, push_bundle_size))/* unicast */
        count++;

    gc_free(&gc);
    return count;
}
#undef SEND_PUSH_UPDATE

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
    struct multi_context *m = (struct multi_context *) arg;
    int n_sent = send_push_update(m, NULL, options, 0, PUSH_BUNDLE_SIZE);
    RETURN_UPDATE_STATUS(n_sent);
}

bool
management_callback_send_push_update_by_cid(void *arg, const unsigned long cid, const char *options)
{
    struct multi_context *m = (struct multi_context *) arg;
    bool status;
    struct multi_instance *mi = lookup_by_cid(m, cid);
    if (mi)
    {
        status = send_push_update(NULL, mi, options, 0, PUSH_BUNDLE_SIZE) > 0;
        return status;
    }
    else
    {   
        msg(M_CLIENT, "ERROR: no client found with CID: %lu", cid);
        return false;
    }
}

bool
management_callback_send_push_update_by_cn(void *arg, const char *cn, const char *options)
{
    struct multi_context *m = (struct multi_context *) arg;

    struct hash_iterator hi;
    struct hash_element *he;
    int n_sent = 0;

    hash_iterator_init(m->iter, &hi);
    while ((he = hash_iterator_next(&hi)))
    {
        struct multi_instance *mi = (struct multi_instance *) he->value;
        if (!mi->halt)
        {
            const char *curr_cn = tls_common_name(mi->context.c2.tls_multi, false);
            if (curr_cn && streq(cn, curr_cn))
            {
                n_sent = send_push_update(m, mi, options, UPT_BY_CN, PUSH_BUNDLE_SIZE);
                break;
            }
        }
    }
    hash_iterator_free(&hi);

    RETURN_UPDATE_STATUS(n_sent);
}

bool
management_callback_send_push_update_by_addr(void *arg, const in_addr_t addr, const int port, const char *options)
{
    struct multi_context *m = (struct multi_context *) arg;
    struct hash_iterator hi;
    struct hash_element *he;
    struct openvpn_sockaddr saddr;
    struct mroute_addr maddr;
    int n_sent = 0;

    CLEAR(saddr);
    saddr.addr.in4.sin_family = AF_INET;
    saddr.addr.in4.sin_addr.s_addr = htonl(addr);
    saddr.addr.in4.sin_port = htons(port);
    if (mroute_extract_openvpn_sockaddr(&maddr, &saddr, true))
    {
        hash_iterator_init(m->iter, &hi);
        while ((he = hash_iterator_next(&hi)))
        {
            struct multi_instance *mi = (struct multi_instance *) he->value;
            if (!mi->halt && mroute_addr_equal(&maddr, &mi->real))
            {
                n_sent = send_push_update(m, mi, options, UPT_BY_ADDR, PUSH_BUNDLE_SIZE);
                break;
            }
        }
        hash_iterator_free(&hi);
    }
    
    RETURN_UPDATE_STATUS(n_sent);
}
#endif
