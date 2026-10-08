/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2026 OpenVPN Inc <sales@openvpn.net>
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

#include "memdbg.h"

#include "multi.h"
#include "forward.h"
#include "multi_io.h"

#ifdef HAVE_SYS_INOTIFY_H
#include <sys/inotify.h>
#endif

/*
 * Special tags passed to event.[ch] functions
 */
#define MULTI_IO_SOCKET           ((void *)1)
#define MULTI_IO_TUN              ((void *)2)
#define MULTI_IO_SIG              ((void *)3) /* Only on Windows */
#define MULTI_IO_MANAGEMENT       ((void *)4)
#define MULTI_IO_FILE_CLOSE_WRITE ((void *)5)
#define MULTI_IO_DCO              ((void *)6)

#ifndef ENABLE_SMALL
static const char *
pract(int action)
{
    switch (action)
    {
        case TA_UNDEF:
            return "TA_UNDEF";

        case TA_SOCKET_READ:
            return "TA_SOCKET_READ";

        case TA_SOCKET_READ_RESIDUAL:
            return "TA_SOCKET_READ_RESIDUAL";

        case TA_SOCKET_WRITE:
            return "TA_SOCKET_WRITE";

        case TA_SOCKET_WRITE_READY:
            return "TA_SOCKET_WRITE_READY";

        case TA_SOCKET_WRITE_DEFERRED:
            return "TA_SOCKET_WRITE_DEFERRED";

        case TA_TUN_READ:
            return "TA_TUN_READ";

        case TA_TUN_WRITE:
            return "TA_TUN_WRITE";

        case TA_TIMEOUT:
            return "TA_TIMEOUT";

        case TA_TUN_WRITE_TIMEOUT:
            return "TA_TUN_WRITE_TIMEOUT";

        case TA_INSTANCE_POST:
            return "TA_INSTANCE_POST";

        default:
            return "?";
    }
}
#endif

static inline struct context *
multi_get_context(struct multi_context *m, struct multi_instance *mi)
{
    if (mi)
    {
        return &mi->context;
    }
    else
    {
        return &m->top;
    }
}

struct multi_io *
multi_io_init(const int maxclients)
{
    struct multi_io *multi_io;

    ASSERT(maxclients >= 1);

    ALLOC_OBJ_CLEAR(multi_io, struct multi_io);
    multi_io->maxevents = maxclients + BASE_N_EVENTS;
    multi_io->es = event_set_init(&multi_io->maxevents, 0);
    wait_signal(multi_io->es, MULTI_IO_SIG);
    ALLOC_ARRAY(multi_io->esr, struct event_set_return, multi_io->maxevents);
    msg(D_MULTI_LOW, "MULTI IO: MULTI_IO INIT maxclients=%d maxevents=%d", maxclients,
        multi_io->maxevents);
    return multi_io;
}

void
multi_io_free(struct multi_io *multi_io)
{
    if (multi_io)
    {
        event_free(multi_io->es);
        free(multi_io->esr);
        free(multi_io);
    }
}

int
multi_io_wait(struct multi_context *m)
{
    int status;
    unsigned int *persistent = &m->multi_io->tun_rwflags;

    for (int i = 0; i < m->top.c1.link_sockets_num; i++)
    {
        struct link_socket *sock = m->top.c2.link_sockets[i];

        if (proto_is_dgram(sock->info.proto))
        {
            multi_io_process_flags(&m->top, m->multi_io->es, sock, IOW_READ | IOW_WAIT_SIGNAL);
        }
        else if (!tuntap_is_dco_win(m->top.c1.tuntap))
        {
            socket_set_listen_persistent(sock, m->multi_io->es, &sock->ev_arg);
        }
    }

    tun_set(m->top.c1.tuntap, m->multi_io->es, EVENT_READ, MULTI_IO_TUN, persistent);
#if defined(ENABLE_DCO)
    dco_event_set(&m->top.c1.tuntap->dco, m->multi_io->es, MULTI_IO_DCO);
#endif

#ifdef ENABLE_MANAGEMENT
    if (management)
    {
        management_socket_set(management, m->multi_io->es, MULTI_IO_MANAGEMENT,
                              &m->multi_io->management_persist_flags);
    }
#endif

#ifdef ENABLE_ASYNC_PUSH
    /* arm inotify watcher */
    event_ctl(m->multi_io->es, m->top.c2.inotify_fd, EVENT_READ, MULTI_IO_FILE_CLOSE_WRITE);
#endif

    status =
        event_wait(m->multi_io->es, &m->top.c2.timeval, m->multi_io->esr, m->multi_io->maxevents);
    update_time();
    m->multi_io->n_esr = 0;
    if (status > 0)
    {
        m->multi_io->n_esr = status;
    }
    return status;
}

static int
multi_io_wait_lite(struct multi_context *m, struct multi_instance *mi, const int action,
                   bool *tun_input_pending)
{
    struct context *c = multi_get_context(m, mi);
    unsigned int looking_for = 0;

    dmsg(D_MULTI_DEBUG, "MULTI IO: multi_io_wait_lite a=%s mi=" ptr_format, pract(action),
         (ptr_type)mi);

    tv_clear(&c->c2.timeval); /* ZERO-TIMEOUT */

    switch (action)
    {
        case TA_TUN_WRITE:
            looking_for = TUN_WRITE;
            tun_input_pending = NULL;
            /* For some reason, the Linux 2.2 TUN/TAP driver hits this timeout */
            c->c2.timeval.tv_sec = 1;
            io_wait(c, IOW_TO_TUN);
            break;

        case TA_SOCKET_WRITE:
            looking_for = SOCKET_WRITE;
            io_wait(c, IOW_TO_LINK | IOW_READ_TUN_FORCE);
            break;

        default:
            msg(M_FATAL, "MULTI IO: multi_io_wait_lite, unhandled action=%d", action);
    }

    if (tun_input_pending && (c->c2.event_set_status & TUN_READ))
    {
        *tun_input_pending = true;
    }

    if (c->c2.event_set_status & looking_for)
    {
        return action;
    }
    else
    {
        switch (action)
        {
            /* MULTI PROTOCOL socket output buffer is full */
            case TA_SOCKET_WRITE:
                return TA_SOCKET_WRITE_DEFERRED;

            /* TUN device timed out on accepting write */
            case TA_TUN_WRITE:
                return TA_TUN_WRITE_TIMEOUT;
        }

        return TA_UNDEF;
    }
}

/**
 * Send a packet over the virtual tun/tap network interface to its locally
 * reachable destination.
 * @ingroup internal_multiplexer
 *
 * This function calls \c process_outgoing_tun() to perform the actual
 * sending of the packet.  Afterwards, it calls \c multi_process_post() to
 * perform server-mode postprocessing.
 *
 * @param m            - The single \c multi_context structure.
 * @param mi           - The \c multi_instance with the packet to send.
 * @param mpp_flags    - Fast I/O optimization flags.
 *
 * @return
 *  - True, if the \c multi_instance associated with the packet sent was
 *    not closed due to a signal during processing.
 *  - Falls, if the \c multi_instance was closed.
 */
static bool
multi_io_write_tun(struct multi_context *m, struct multi_instance *mi, const unsigned int mpp_flags)
{
    bool ret = true;

#ifdef MULTI_DEBUG_EVENT_LOOP
    printf("%s -> TUN len=%d\n", id(mi), mi->context.c2.to_tun.len);
#endif
    set_prefix(mi);
    vlan_process_outgoing_tun(m, mi);
    process_outgoing_tun(&mi->context, mi->context.c2.link_sockets[0]);
    ret = multi_process_post(m, mi, mpp_flags);
    clear_prefix();
    return ret;
}

/*
 * Drop a TUN/TAP outgoing packet..
 */
static void
multi_io_drop_tun(struct multi_context *m, struct multi_instance *mi, const unsigned int mpp_flags)
{
    set_prefix(mi);

    msg(D_MULTI_ERRORS, "MULTI: Outgoing TUN queue full, dropped packet len=%d",
        mi->context.c2.to_tun.len);

    buf_reset(&mi->context.c2.to_tun);

    multi_process_post(m, mi, mpp_flags);
    clear_prefix();
}

/*
 * Determine which instance has output for the
 * link: mi itself, or else the next queued
 * bcast/c2c packet, prepared in its to_link buffer.
 */
static struct multi_instance *
multi_io_write_link_pre(struct multi_context *m, struct multi_instance *mi)
{
    if (mi && LINK_OUT(&mi->context))
    {
        return mi;
    }
    if (mbuf_defined(m->mbuf))
    {
        return multi_get_queue(m->mbuf);
    }
    return NULL;
}

static bool
multi_io_send_link(struct multi_context *m, struct multi_instance *mi, const unsigned int mpp_flags)
{
    bool ret = true;
    set_prefix(mi);
    process_outgoing_link(&mi->context, mi->context.c2.link_sockets[0]);
    ret = multi_process_post(m, mi, mpp_flags);
    clear_prefix();
    return ret;
}

static bool
multi_io_write_link_deferred(struct multi_context *m, struct multi_instance *mi,
                             const unsigned int mpp_flags)
{
    struct mbuf_item item;
    bool ret = true;
    ASSERT(mi);

    /* extract from queue */
    if (mbuf_extract_item(mi->tcp_link_out_deferred, &item)) /* ciphertext IP packet */
    {
        dmsg(D_MULTI_TCP, "MULTI TCP: transmitting previously deferred packet");

        ASSERT(mi == item.instance);
        mi->context.c2.to_link = item.buffer->buf;
        ret = multi_io_send_link(m, mi, mpp_flags);
        mbuf_free_buf(item.buffer);
    }
    return ret;
}

static bool
multi_io_write_link(struct multi_context *m, struct multi_instance *mi, bool defer,
                    const unsigned int mpp_flags)
{
    bool ret = true;

    mi = multi_io_write_link_pre(m, mi);
    if (mi)
    {
        if ((defer && !proto_is_dgram(mi->context.c2.link_sockets[0]->info.proto))
            || mbuf_defined(mi->tcp_link_out_deferred))
        {
            /* save to queue */
            struct buffer *buf = &mi->context.c2.to_link;
            if (BLEN(buf) > 0)
            {
                struct mbuf_buffer *mb = mbuf_alloc_buf(buf);
                struct mbuf_item item;

                set_prefix(mi);
                dmsg(D_MULTI_TCP, "MULTI TCP: queuing deferred packet");
                item.buffer = mb;
                item.instance = mi;
                mbuf_add_item(mi->tcp_link_out_deferred, &item);
                mbuf_free_buf(mb);
                buf_reset(buf);
                ret = multi_process_post(m, mi, mpp_flags);
                clear_prefix();
            }
        }
        else
        {
            ret = multi_io_send_link(m, mi, mpp_flags);
        }
    }
    return ret;
}

static struct multi_instance *
multi_io_dispatch(struct multi_context *m, struct multi_instance *mi, struct link_socket *sock,
                  const int action)
{
    const unsigned int mpp_flags = MPP_PRE_SELECT | MPP_RECORD_TOUCH;
    struct multi_instance *touched = mi;
    // cppcheck-suppress autoVariables ; yes, we know this is dangerous
    m->mpp_touched = &touched;

    dmsg(D_MULTI_DEBUG, "MULTI IO: multi_io_dispatch a=%s mi=" ptr_format, pract(action),
         (ptr_type)mi);

    switch (action)
    {
        case TA_TUN_READ:
            read_incoming_tun(&m->top);
            if (!IS_SIG(&m->top))
            {
                multi_process_incoming_tun(m, mpp_flags);
            }
            break;

        case TA_SOCKET_READ:
        case TA_SOCKET_READ_RESIDUAL:
        {
            struct context *c = multi_get_context(m, mi);

            if (mi)
            {
                ASSERT(mi->context.c2.link_sockets);
                sock = mi->context.c2.link_sockets[0];
                set_prefix(mi);
            }
            ASSERT(sock);
            read_incoming_link(c, sock);
            clear_prefix();
            if (!IS_SIG(c))
            {
                multi_process_incoming_link(m, mi, mpp_flags, sock);
                if (!IS_SIG(c))
                {
                    stream_buf_read_setup(sock);
                }
            }
            break;
        }

        case TA_TIMEOUT:
            multi_process_timeout(m, mpp_flags);
            break;

        case TA_TUN_WRITE:
            ASSERT(mi);
            multi_io_write_tun(m, mi, mpp_flags);
            break;

        case TA_TUN_WRITE_TIMEOUT:
            ASSERT(mi);
            multi_io_drop_tun(m, mi, mpp_flags);
            break;

        case TA_SOCKET_WRITE_READY:
            ASSERT(mi);
            multi_io_write_link_deferred(m, mi, mpp_flags);
            break;

        case TA_SOCKET_WRITE:
            multi_io_write_link(m, mi, false, mpp_flags);
            break;

        case TA_SOCKET_WRITE_DEFERRED:
            multi_io_write_link(m, mi, true, mpp_flags);
            break;

        case TA_INSTANCE_POST:
            ASSERT(mi);
            multi_process_post(m, mi, mpp_flags);
            break;

        default:
            msg(M_FATAL, "MULTI IO: multi_io_dispatch, unhandled action=%d", action);
    }

    m->mpp_touched = NULL;
    return touched;
}

static int
multi_io_post(struct multi_context *m, struct multi_instance *mi, const int action)
{
    struct context *c = multi_get_context(m, mi);
    int newaction = TA_UNDEF;

#define MTP_NONE     0
#define MTP_TUN_OUT  (1 << 0)
#define MTP_LINK_OUT (1 << 1)
    unsigned int flags = MTP_NONE;

    if (TUN_OUT(c))
    {
        flags |= MTP_TUN_OUT;
    }
    if (LINK_OUT(c))
    {
        flags |= MTP_LINK_OUT;
    }

    switch (flags)
    {
        case MTP_TUN_OUT | MTP_LINK_OUT:
        case MTP_TUN_OUT:
            newaction = TA_TUN_WRITE;
            break;

        case MTP_LINK_OUT:
            newaction = TA_SOCKET_WRITE;
            break;

        case MTP_NONE:
            if (mi && link_socket_connection_oriented(mi->context.c2.link_sockets[0]))
            {
                if (sockets_read_residual(c))
                {
                    newaction = TA_SOCKET_READ_RESIDUAL;
                }
                else
                {
                    multi_tcp_set_global_rw_flags(m, mi);
                }
            }
            break;

        default:
        {
            struct gc_arena gc = gc_new();
            msg(M_FATAL, "MULTI IO: multi_io_post bad state, mi=%s flags=%u",
                multi_instance_string(mi, false, &gc), flags);
            gc_free(&gc);
            break;
        }
    }

    dmsg(D_MULTI_DEBUG, "MULTI IO: multi_io_post %s -> %s", pract(action), pract(newaction));

    return newaction;
}

void
multi_io_process_io(struct multi_context *m)
{
    struct multi_io *multi_io = m->multi_io;
    int i;

    for (i = 0; i < multi_io->n_esr; ++i)
    {
        struct event_set_return *e = &multi_io->esr[i];
        struct event_arg *ev_arg = (struct event_arg *)e->arg;

        /* incoming data for instance or listening socket? */
        if (e->arg >= MULTI_N)
        {
            switch (ev_arg->type)
            {
                struct multi_instance *mi;

                /* react to event on child instance */
                case EVENT_ARG_MULTI_INSTANCE:
                    if (!ev_arg->u.mi)
                    {
                        msg(D_MULTI_ERRORS, "MULTI IO: multi_io_proc_io: null minstance");
                        break;
                    }

                    mi = ev_arg->u.mi;
                    if (e->rwflags & EVENT_WRITE)
                    {
                        multi_io_action(m, mi, NULL, TA_SOCKET_WRITE_READY, false);
                    }
                    else if (e->rwflags & EVENT_READ)
                    {
                        multi_io_action(m, mi, NULL, TA_SOCKET_READ, false);
                    }
                    break;

                case EVENT_ARG_LINK_SOCKET:
                    if (!ev_arg->u.sock)
                    {
                        msg(D_MULTI_ERRORS, "MULTI IO: multi_io_proc_io: null socket");
                        break;
                    }
                    /* new incoming TCP client attempting to connect? */
                    if (!proto_is_dgram(ev_arg->u.sock->info.proto))
                    {
                        socket_reset_listen_persistent(ev_arg->u.sock);
                        mi = multi_create_instance_tcp(m, ev_arg->u.sock);
                        /* monitor and/or handle events that are
                         * triggered in succession by the first one
                         * before returning to the main loop. */
                        if (mi)
                        {
                            multi_io_action(m, mi, NULL, TA_INSTANCE_POST, false);
                        }
                    }
                    else if (e->rwflags & EVENT_READ)
                    {
                        multi_io_action(m, NULL, ev_arg->u.sock, TA_SOCKET_READ, false);
                    }
                    break;
            }
        }
        else
        {
#ifdef ENABLE_MANAGEMENT
            if (e->arg == MULTI_IO_MANAGEMENT)
            {
                ASSERT(management);
                management_io(management);
            }
            else
#endif
                /* incoming data on TUN? */
                if (e->arg == MULTI_IO_TUN)
                {
                    if (e->rwflags & EVENT_READ)
                    {
                        multi_io_action(m, NULL, NULL, TA_TUN_READ, false);
                    }
                }

#if defined(ENABLE_DCO)
                /* incoming data on DCO? */
                else if (e->arg == MULTI_IO_DCO)
                {
                    dco_read_and_process(&m->top.c1.tuntap->dco);
                }
#endif
                /* signal received? */
                else if (e->arg == MULTI_IO_SIG)
                {
                    get_signal(&m->top.sig->signal_received);
                }
#ifdef ENABLE_ASYNC_PUSH
                else if (e->arg == MULTI_IO_FILE_CLOSE_WRITE)
                {
                    multi_process_file_closed(m);
                }
#endif
        }
        if (IS_SIG(&m->top))
        {
            break;
        }
    }
    multi_io->n_esr = 0;

    /*
     * Drain the queued mbuf packets, datagram and TCP instances alike
     */
    {
        struct multi_instance *mi;
        while (!IS_SIG(&m->top) && (mi = mbuf_peek(m->mbuf)) != NULL)
        {
            multi_io_action(m, mi, NULL, TA_SOCKET_WRITE, true);
        }
    }
}

void
multi_io_action(struct multi_context *m, struct multi_instance *mi, struct link_socket *sock,
                int action, bool poll)
{
    bool tun_input_pending = false;

    do
    {
        dmsg(D_MULTI_DEBUG, "MULTI IO: multi_io_action a=%s p=%d", pract(action), poll);

        /*
         * If TA_SOCKET_READ_RESIDUAL, it means we still have pending
         * input packets which were read by a prior recv.
         *
         * Otherwise do a "lite" wait, which means we wait with 0 timeout
         * on I/O events only related to the current instance, not
         * the big list of events.
         *
         * On our first pass, poll will be false because we already know
         * that input is available, and to call io_wait would be redundant.
         */
        if (poll && action != TA_SOCKET_READ_RESIDUAL)
        {
            const int orig_action = action;
            action = multi_io_wait_lite(m, mi, action, &tun_input_pending);
            if (action == TA_UNDEF)
            {
                msg(M_FATAL, "MULTI IO: I/O wait required blocking in multi_io_action, action=%d",
                    orig_action);
            }
        }

        /*
         * Dispatch the action
         */
        struct multi_instance *touched = multi_io_dispatch(m, mi, sock, action);

        /*
         * Signal received or connection
         * reset by peer?
         */
        if (touched && IS_SIG(&touched->context))
        {
            if (mi == touched)
            {
                mi = NULL;
            }
            multi_close_instance_on_signal(m, touched);
            touched = NULL;
        }

        /*
         * touched is the only instance this action
         * post-processed: having closed it above if
         * it was signalled, write its output if any.
         */
        if (touched && ANY_OUT(&touched->context))
        {
            mi = touched;
        }

        /*
         * Based on the effects of the action,
         * such as generating pending output,
         * possibly transition to a new action state.
         */
        action = multi_io_post(m, mi, action);

        /*
         * If we are finished processing the original action,
         * check if we have any TUN input.  If so, transition
         * our action state to processing this input.
         */
        if (tun_input_pending && action == TA_UNDEF)
        {
            action = TA_TUN_READ;
            mi = NULL;
            tun_input_pending = false;
            poll = false;
        }
        else
        {
            poll = true;
        }

    } while (action != TA_UNDEF);
}

void
multi_io_delete_event(struct multi_io *multi_io, event_t event)
{
    if (multi_io && multi_io->es)
    {
        event_del(multi_io->es, event);
    }
}
