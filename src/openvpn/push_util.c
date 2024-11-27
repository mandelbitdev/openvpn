#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "push.h"

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

//return index of last ',' or 0 if do not find any
//if there is a comma at index 0 it's an error anyway
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
    int mi = 0;
    while (*str)
    {
        if (strlen(str) + sizeof(push_update_cmd) > safe_cap)// sizeof(push_update_cmd) + ',' - '/0'
        {
            int ci = find_first_comma_of_next_bundle(str, safe_cap - sizeof(push_update_cmd));
            if (!ci)
               return false;//if no commas found go to fail, do not send messages.
            
            str[ci] = '\0';
            mexs[mi] = gc_strdup(str, gc);//copy from i to ci -1;
            i = ci + 1; 
        }
        else
        {
            mexs[mi] = gc_strdup(str, gc);
            i = strlen(str);
        }
        str = &str[i];
        mi++;
    }
    return true;
}


bool
send_push_update(struct context *c, const char *mex)
{
    if (!mex || !*mex)
        return false;
    const int extra = 84; /* extra space for possible trailing ifconfig and push-continuation */
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(PUSH_BUNDLE_SIZE, &gc);
    const int safe_cap = BCAP(&buf) - extra;
    int mlen = strlen(mex);
    int mexnum = (mlen / (safe_cap  - sizeof(push_update_cmd))) + 1;
    char *str = gc_strdup(mex, &gc);
    char **mexs = gc_malloc(sizeof(char *) * (mexnum + 1), true, &gc);
    mexs[mexnum] = NULL;

    
    if (!message_splitter(str, mexs, &gc, safe_cap))
        goto fail;
    
    if (!mexs[0] || !*mexs[0])
    {
        goto fail;
    }
    else if (!mexs[1] || !*mexs[1])
    {
        buf_printf(&buf, "%s%c%s", push_update_cmd, ',', mexs[0]);
        const bool status = send_control_channel_string(c, BSTR(&buf), D_PUSH);
        if (!status)
            goto fail;
    }
    else
    {
        int i = 0;
        while(mexs[i] && *mexs[i])
        {
            if (mexs[i+1])
                buf_printf(&buf, "%s%c%s%s", push_update_cmd, ',', mexs[i], ",push-continuation 2");
            else
                buf_printf(&buf, "%s%c%s%s", push_update_cmd, ',', mexs[i], ",push-continuation 1");

            const bool status = send_control_channel_string(c, BSTR(&buf), D_PUSH);
            if (!status)//should send buf with push-continuation 1 if it fails?
                goto fail;
            buf = alloc_buf_gc(PUSH_BUNDLE_SIZE, &gc);
            i++;
        }
    }

    gc_free(&gc);
    return true;

fail:
    gc_free(&gc);
    return false;
}
