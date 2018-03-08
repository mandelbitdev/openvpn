/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2018 OpenVPN Inc <sales@openvpn.net>
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
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#include "forward.h"
#include "init.h"
#include "push.h"
#include "gremlin.h"
#include "mss.h"
#include "event.h"
#include "ps.h"
#include "dhcp.h"
#include "common.h"
#include "ssl_verify.h"

#include "memdbg.h"

#include "forward-inline.h"
#include "occ-inline.h"
#include "ping-inline.h"
#include "mstats.h"

counter_type link_read_bytes_global;  /* GLOBAL */
counter_type link_write_bytes_global; /* GLOBAL */

/* show event wait debugging info */

#ifdef ENABLE_DEBUG

const char *
wait_status_string(struct context *c, struct gc_arena *gc)
{
    struct buffer out = alloc_buf_gc(64, gc);
    buf_printf(&out, "I/O WAIT %s|%s|%s|%s %s",
               tun_stat(c->c1.tuntap, EVENT_READ, gc),
               tun_stat(c->c1.tuntap, EVENT_WRITE, gc),
               socket_stat(c->c2.link_socket, EVENT_READ, gc),
               socket_stat(c->c2.link_socket, EVENT_WRITE, gc),
               tv_string(&c->c2.timeval, gc));
    return BSTR(&out);
}

void
show_wait_status(struct context *c)
{
    struct gc_arena gc = gc_new();
    dmsg(D_EVENT_WAIT, "%s", wait_status_string(c, &gc));
    gc_free(&gc);
}

#endif /* ifdef ENABLE_DEBUG */

/*
 * In TLS mode, let TLS level respond to any control-channel
 * packets which were received, or prepare any packets for
 * transmission.
 *
 * tmp_int is purely an optimization that allows us to call
 * tls_multi_process less frequently when there's not much
 * traffic on the control-channel.
 *
 */
void
check_tls_dowork(struct context *c)
{
    interval_t wakeup = BIG_TIMEOUT;

    if (interval_test(&c->c2.tmp_int))
    {
        const int tmp_status = tls_multi_process
                                   (c->c2.tls_multi, &c->c2.to_link, &c->c2.to_link_addr,
                                   get_link_socket_info(c), &wakeup);
        if (tmp_status == TLSMP_ACTIVE)
        {
            update_time();
            interval_action(&c->c2.tmp_int);
        }
        else if (tmp_status == TLSMP_KILL)
        {
            register_signal(c, SIGTERM, "auth-control-exit");
        }

        interval_future_trigger(&c->c2.tmp_int, wakeup);
    }

    interval_schedule_wakeup(&c->c2.tmp_int, &wakeup);

    if (wakeup)
    {
        context_reschedule_sec(c, wakeup);
    }
}

void
check_tls_errors_co(struct context *c)
{
    msg(D_STREAM_ERRORS, "Fatal TLS error (check_tls_errors_co), restarting");
    register_signal(c, c->c2.tls_exit_signal, "tls-error"); /* SOFT-SIGUSR1 -- TLS error */
}

void
check_tls_errors_nco(struct context *c)
{
    register_signal(c, c->c2.tls_exit_signal, "tls-error"); /* SOFT-SIGUSR1 -- TLS error */
}

#if P2MP

/*
 * Handle incoming configuration
 * messages on the control channel.
 */
void
check_incoming_control_channel_dowork(struct context *c)
{
    const int len = tls_test_payload_len(c->c2.tls_multi);
    if (len)
    {
        struct gc_arena gc = gc_new();
        struct buffer buf = alloc_buf_gc(len, &gc);
        if (tls_rec_payload(c->c2.tls_multi, &buf))
        {
            /* force null termination of message */
            buf_null_terminate(&buf);

            /* enforce character class restrictions */
            string_mod(BSTR(&buf), CC_PRINT, CC_CRLF, 0);

            if (buf_string_match_head_str(&buf, "AUTH_FAILED"))
            {
                receive_auth_failed(c, &buf);
            }
            else if (buf_string_match_head_str(&buf, "PUSH_"))
            {
                incoming_push_message(c, &buf);
            }
            else if (buf_string_match_head_str(&buf, "RESTART"))
            {
                server_pushed_signal(c, &buf, true, 7);
            }
            else if (buf_string_match_head_str(&buf, "HALT"))
            {
                server_pushed_signal(c, &buf, false, 4);
            }
            else
            {
                msg(D_PUSH_ERRORS, "WARNING: Received unknown control message: %s", BSTR(&buf));
            }
        }
        else
        {
            msg(D_PUSH_ERRORS, "WARNING: Receive control message failed");
        }

        gc_free(&gc);
    }
}

/*
 * Periodically resend PUSH_REQUEST until PUSH message received
 */
void
check_push_request_dowork(struct context *c)
{
    send_push_request(c);

    /* if no response to first push_request, retry at PUSH_REQUEST_INTERVAL second intervals */
    event_timeout_modify_wakeup(&c->c2.push_request_interval, PUSH_REQUEST_INTERVAL);
}

#endif /* P2MP */

/*
 * Things that need to happen immediately after connection initiation should go here.
 */
void
check_connection_established_dowork(struct context *c)
{
    if (event_timeout_trigger(&c->c2.wait_for_connect, &c->c2.timeval, ETT_DEFAULT))
    {
        if (CONNECTION_ESTABLISHED(c))
        {
#if P2MP
            /* if --pull was specified, send a push request to server */
            if (c->c2.tls_multi && c->options.pull)
            {
#ifdef ENABLE_MANAGEMENT
                if (management)
                {
                    management_set_state(management,
                                         OPENVPN_STATE_GET_CONFIG,
                                         NULL,
                                         NULL,
                                         NULL,
                                         NULL,
                                         NULL);
                }
#endif
                /* fire up push request right away (already 1s delayed) */
                event_timeout_init(&c->c2.push_request_interval, 0, now);
                reset_coarse_timers(c);
            }
            else
#endif /* if P2MP */
            {
                do_up(c, false, 0);
            }

            event_timeout_clear(&c->c2.wait_for_connect);
        }
    }
}

/*
 * Send a string to remote over the TLS control channel.
 * Used for push/pull messages, passing username/password,
 * etc.
 */
bool
send_control_channel_string(struct context *c, const char *str, int msglevel)
{
    if (c->c2.tls_multi)
    {
        struct gc_arena gc = gc_new();
        bool stat;

        /* buffered cleartext write onto TLS control channel */
        stat = tls_send_payload(c->c2.tls_multi, (uint8_t *) str, strlen(str) + 1);

        /*
         * Reschedule tls_multi_process.
         * NOTE: in multi-client mode, usually the below two statements are
         * insufficient to reschedule the client instance object unless
         * multi_schedule_context_wakeup(m, mi) is also called.
         */
        interval_action(&c->c2.tmp_int);
        context_immediate_reschedule(c); /* ZERO-TIMEOUT */

        msg(msglevel, "SENT CONTROL [%s]: '%s' (status=%d)",
            tls_common_name(c->c2.tls_multi, false),
            sanitize_control_message(str, &gc),
            (int) stat);

        gc_free(&gc);
        return stat;
    }
    return true;
}

/*
 * Add routes.
 */

static void
check_add_routes_action(struct context *c, const bool errors)
{
    do_route(&c->options, c->c1.route_list, c->c1.route_ipv6_list,
             c->c1.tuntap, c->plugins, c->c2.es);
    update_time();
    event_timeout_clear(&c->c2.route_wakeup);
    event_timeout_clear(&c->c2.route_wakeup_expire);
    initialization_sequence_completed(c, errors ? ISC_ERRORS : 0); /* client/p2p --route-delay was defined */
}

void
check_add_routes_dowork(struct context *c)
{
    if (test_routes(c->c1.route_list, c->c1.tuntap))
    {
        check_add_routes_action(c, false);
    }
    else if (event_timeout_trigger(&c->c2.route_wakeup_expire, &c->c2.timeval, ETT_DEFAULT))
    {
        check_add_routes_action(c, true);
    }
    else
    {
        msg(D_ROUTE, "Route: Waiting for TUN/TAP interface to come up...");
        if (c->c1.tuntap)
        {
            if (!tun_standby(c->c1.tuntap))
            {
                register_signal(c, SIGHUP, "ip-fail");
                c->persist.restart_sleep_seconds = 10;
#ifdef _WIN32
                show_routes(M_INFO|M_NOPREFIX);
                show_adapters(M_INFO|M_NOPREFIX);
#endif
            }
        }
        update_time();
        if (c->c2.route_wakeup.n != 1)
        {
            event_timeout_init(&c->c2.route_wakeup, 1, now);
        }
        event_timeout_reset(&c->c2.ping_rec_interval);
    }
}

/*
 * Should we exit due to inactivity timeout?
 */
void
check_inactivity_timeout_dowork(struct context *c)
{
    msg(M_INFO, "Inactivity timeout (--inactive), exiting");
    register_signal(c, SIGTERM, "inactive");
}

int
get_server_poll_remaining_time(struct event_timeout *server_poll_timeout)
{
    update_time();
    int remaining = event_timeout_remaining(server_poll_timeout);
    return max_int(0, remaining);
}
#if P2MP

void
check_server_poll_timeout_dowork(struct context *c)
{
    event_timeout_reset(&c->c2.server_poll_interval);
    ASSERT(c->c2.tls_multi);
    if (!tls_initial_packet_received(c->c2.tls_multi))
    {
        msg(M_INFO, "Server poll timeout, restarting");
        register_signal(c, SIGUSR1, "server_poll");
        c->persist.restart_sleep_seconds = -1;
    }
}

/*
 * Schedule a signal n_seconds from now.
 */
void
schedule_exit(struct context *c, const int n_seconds, const int signal)
{
    tls_set_single_session(c->c2.tls_multi);
    update_time();
    reset_coarse_timers(c);
    event_timeout_init(&c->c2.scheduled_exit, n_seconds, now);
    c->c2.scheduled_exit_signal = signal;
    msg(D_SCHED_EXIT, "Delayed exit in %d seconds", n_seconds);
}

/*
 * Scheduled exit?
 */
void
check_scheduled_exit_dowork(struct context *c)
{
    register_signal(c, c->c2.scheduled_exit_signal, "delayed-exit");
}

#endif /* if P2MP */

/*
 * Should we write timer-triggered status file.
 */
void
check_status_file_dowork(struct context *c)
{
    if (c->c1.status_output)
    {
        print_status(c, c->c1.status_output);
    }
}

#ifdef ENABLE_FRAGMENT
/*
 * Should we deliver a datagram fragment to remote?
 */
void
check_fragment_dowork(struct context *c)
{
    struct link_socket_info *lsi = get_link_socket_info(c);

    /* OS MTU Hint? */
    if (lsi->mtu_changed)
    {
        frame_adjust_path_mtu(&c->c2.frame_fragment, c->c2.link_socket->mtu,
                              c->options.ce.proto);
        lsi->mtu_changed = false;
    }

    if (fragment_outgoing_defined(c->c2.fragment))
    {
        if (!c->c2.to_link.len)
        {
            /* encrypt a fragment for output to TCP/UDP port */
            ASSERT(fragment_ready_to_send(c->c2.fragment, &c->c2.buf, &c->c2.frame_fragment));
            encrypt_sign(c, false);
        }
    }

    fragment_housekeeping(c->c2.fragment, &c->c2.frame_fragment, &c->c2.timeval);
}
#endif /* ifdef ENABLE_FRAGMENT */

/*
 * Buffer reallocation, for use with null encryption.
 */
static inline void
buffer_turnover(const uint8_t *orig_buf, struct buffer *dest_stub, struct buffer *src_stub, struct buffer *storage)
{
    if (orig_buf == src_stub->data && src_stub->data != storage->data)
    {
        buf_assign(storage, src_stub);
        *dest_stub = *storage;
    }
    else
    {
        *dest_stub = *src_stub;
    }
}

/*
 * Compress, fragment, encrypt and HMAC-sign an outgoing packet.
 * Input: c->c2.buf
 * Output: c->c2.to_link
 */
void
encrypt_sign(struct context *c, bool comp_frag)
{
    struct context_buffers *b = c->c2.buffers;
    const uint8_t *orig_buf = c->c2.buf.data;
    struct crypto_options *co = NULL;

#if P2MP_SERVER
    /*
     * Drop non-TLS outgoing packet if client-connect script/plugin
     * has not yet succeeded.
     */
    if (c->c2.context_auth != CAS_SUCCEEDED)
    {
        c->c2.buf.len = 0;
    }
#endif

    if (comp_frag)
    {
#ifdef USE_COMP
        /* Compress the packet. */
        if (c->c2.comp_context)
        {
            (*c->c2.comp_context->alg.compress)(&c->c2.buf, b->compress_buf, c->c2.comp_context, &c->c2.frame);
        }
#endif
#ifdef ENABLE_FRAGMENT
        if (c->c2.fragment)
        {
            fragment_outgoing(c->c2.fragment, &c->c2.buf, &c->c2.frame_fragment);
        }
#endif
    }

    /* initialize work buffer with FRAME_HEADROOM bytes of prepend capacity */
    ASSERT(buf_init(&b->encrypt_buf, FRAME_HEADROOM(&c->c2.frame)));

    if (c->c2.tls_multi)
    {
        /* Get the key we will use to encrypt the packet. */
        tls_pre_encrypt(c->c2.tls_multi, &c->c2.buf, &co);
        /* If using P_DATA_V2, prepend the 1-byte opcode and 3-byte peer-id to the
         * packet before openvpn_encrypt(), so we can authenticate the opcode too.
         */
        if (c->c2.buf.len > 0 && c->c2.tls_multi->use_peer_id)
        {
            tls_prepend_opcode_v2(c->c2.tls_multi, &b->encrypt_buf);
        }
    }
    else
    {
        co = &c->c2.crypto_options;
    }

    /* Encrypt and authenticate the packet */
    openvpn_encrypt(&c->c2.buf, b->encrypt_buf, co);

    /* Do packet administration */
    if (c->c2.tls_multi)
    {
        if (c->c2.buf.len > 0 && !c->c2.tls_multi->use_peer_id)
        {
            tls_prepend_opcode_v1(c->c2.tls_multi, &c->c2.buf);
        }
        tls_post_encrypt(c->c2.tls_multi, &c->c2.buf);
    }

    /*
     * Get the address we will be sending the packet to.
     */
    link_socket_get_outgoing_addr(&c->c2.buf, get_link_socket_info(c),
                                  &c->c2.to_link_addr);

    /* if null encryption, copy result to read_tun_buf */
    buffer_turnover(orig_buf, &c->c2.to_link, &c->c2.buf, &b->read_tun_buf);
}

/*
 * Coarse timers work to 1 second resolution.
 */
static void
process_coarse_timers(struct context *c)
{
    /* flush current packet-id to file once per 60
     * seconds if --replay-persist was specified */
    check_packet_id_persist_flush(c);

    /* should we update status file? */
    check_status_file(c);

    /* process connection establishment items */
    check_connection_established(c);

#if P2MP
    /* see if we should send a push_request in response to --pull */
    check_push_request(c);
#endif

#ifdef PLUGIN_PF
    pf_check_reload(c);
#endif

    /* process --route options */
    check_add_routes(c);

    /* possibly exit due to --inactive */
    check_inactivity_timeout(c);
    if (c->sig->signal_received)
    {
        return;
    }

    /* restart if ping not received */
    check_ping_restart(c);
    if (c->sig->signal_received)
    {
        return;
    }

#if P2MP
    if (c->c2.tls_multi)
    {
        check_server_poll_timeout(c);
        if (c->sig->signal_received)
        {
            return;
        }

        check_scheduled_exit(c);
        if (c->sig->signal_received)
        {
            return;
        }
    }
#endif

#ifdef ENABLE_OCC
    /* Should we send an OCC_REQUEST message? */
    check_send_occ_req(c);

    /* Should we send an MTU load test? */
    check_send_occ_load_test(c);

    /* Should we send an OCC_EXIT message to remote? */
    if (c->c2.explicit_exit_notification_time_wait)
    {
        process_explicit_exit_notification_timer_wakeup(c);
    }
#endif

    /* Should we ping the remote? */
    check_ping_send(c);
}

static void
check_coarse_timers_dowork(struct context *c)
{
    const struct timeval save = c->c2.timeval;
    c->c2.timeval.tv_sec = BIG_TIMEOUT;
    c->c2.timeval.tv_usec = 0;
    process_coarse_timers(c);
    c->c2.coarse_timer_wakeup = now + c->c2.timeval.tv_sec;

    dmsg(D_INTERVAL, "TIMER: coarse timer wakeup %"PRIi64" seconds", (int64_t)c->c2.timeval.tv_sec);

    /* Is the coarse timeout NOT the earliest one? */
    if (c->c2.timeval.tv_sec > save.tv_sec)
    {
        c->c2.timeval = save;
    }
}

static inline void
check_coarse_timers(struct context *c)
{
    const time_t local_now = now;
    if (local_now >= c->c2.coarse_timer_wakeup)
    {
        check_coarse_timers_dowork(c);
    }
    else
    {
        context_reschedule_sec(c, c->c2.coarse_timer_wakeup - local_now);
    }
}

static void
check_timeout_random_component_dowork(struct context *c)
{
    const int update_interval = 10; /* seconds */
    c->c2.update_timeout_random_component = now + update_interval;
    c->c2.timeout_random_component.tv_usec = (time_t) get_random() & 0x0003FFFF;
    c->c2.timeout_random_component.tv_sec = 0;

    dmsg(D_INTERVAL, "RANDOM USEC=%ld", (long) c->c2.timeout_random_component.tv_usec);
}

static inline void
check_timeout_random_component(struct context *c)
{
    if (now >= c->c2.update_timeout_random_component)
    {
        check_timeout_random_component_dowork(c);
    }
    if (c->c2.timeval.tv_sec >= 1)
    {
        tv_add(&c->c2.timeval, &c->c2.timeout_random_component);
    }
}

/*
 * Handle addition and removal of the 10-byte Socks5 header
 * in UDP packets.
 */

static inline void
socks_postprocess_incoming_link(struct context *c, struct link_socket *ls)
{
    if (ls->socks_proxy && ls->info.proto == PROTO_UDP)
    {
        socks_process_incoming_udp(&c->c2.buf, &c->c2.from);
    }
}

static inline void
socks_preprocess_outgoing_link(struct context *c,
                               struct link_socket *ls,
                               struct link_socket_actual **to_addr,
                               int *size_delta)
{
    if (ls->socks_proxy && ls->info.proto == PROTO_UDP)
    {
        *size_delta += socks_process_outgoing_udp(&c->c2.to_link, c->c2.to_link_addr);
        *to_addr = &ls->socks_relay;
    }
}

/* undo effect of socks_preprocess_outgoing_link */
static inline void
link_socket_write_post_size_adjust(int *size,
                                   int size_delta,
                                   struct buffer *buf)
{
    if (size_delta > 0 && *size > size_delta)
    {
        *size -= size_delta;
        if (!buf_advance(buf, size_delta))
        {
            *size = 0;
        }
    }
}

/*
 * Output: c->c2.buf
 */

void
read_incoming_link(struct context *c, struct link_socket *ls)
{
    /*
     * Set up for recvfrom call to read datagram
     * sent to our TCP/UDP port.
     */
    int status;

    /*ASSERT (!c->c2.to_tun.len);*/

    perf_push(PERF_READ_IN_LINK);

    c->c2.buf = c->c2.buffers->read_link_buf;
    ASSERT(buf_init(&c->c2.buf, FRAME_HEADROOM_ADJ(&c->c2.frame, FRAME_HEADROOM_MARKER_READ_LINK)));

    status = link_socket_read(ls,
                              &c->c2.buf,
                              &c->c2.from);

    if (socket_connection_reset(ls, status))
    {
#if PORT_SHARE
        if (port_share && socket_foreign_protocol_detected(ls))
        {
            const struct buffer *fbuf = socket_foreign_protocol_head(ls);
            const int sd = socket_foreign_protocol_sd(ls);
            port_share_redirect(port_share, fbuf, sd);
            register_signal(c, SIGTERM, "port-share-redirect");
        }
        else
#endif
        {
            /* received a disconnect from a connection-oriented protocol */
            if (c->options.inetd)
            {
                register_signal(c, SIGTERM, "connection-reset-inetd");
                msg(D_STREAM_ERRORS, "Connection reset, inetd/xinetd exit [%d]", status);
            }
            else
            {
#ifdef ENABLE_OCC
                if (event_timeout_defined(&c->c2.explicit_exit_notification_interval))
                {
                    msg(D_STREAM_ERRORS, "Connection reset during exit notification period, ignoring [%d]", status);
                    management_sleep(1);
                }
                else
#endif
                {
                    register_signal(c, SIGUSR1, "connection-reset"); /* SOFT-SIGUSR1 -- TCP connection reset */
                    msg(D_STREAM_ERRORS, "Connection reset, restarting [%d]", status);
                }
            }
        }
        perf_pop();
        return;
    }

    /* check recvfrom status */
    check_status(status, "read", ls, NULL);

    /* Remove socks header if applicable */
    socks_postprocess_incoming_link(c, ls);

    perf_pop();
}

bool
process_incoming_link_part1(struct context *c, struct link_socket_info *lsi, bool floated)
{
    struct gc_arena gc = gc_new();
    bool decrypt_status = false;

    if (c->c2.buf.len > 0)
    {
        c->c2.link_read_bytes += c->c2.buf.len;
        link_read_bytes_global += c->c2.buf.len;
#ifdef ENABLE_MEMSTATS
        if (mmap_stats)
        {
            mmap_stats->link_read_bytes = link_read_bytes_global;
        }
#endif
        c->c2.original_recv_size = c->c2.buf.len;
#ifdef ENABLE_MANAGEMENT
        if (management)
        {
            management_bytes_in(management, c->c2.buf.len);
#ifdef MANAGEMENT_DEF_AUTH
            management_bytes_server(management, &c->c2.link_read_bytes, &c->c2.link_write_bytes, &c->c2.mda_context);
#endif
        }
#endif
    }
    else
    {
        c->c2.original_recv_size = 0;
    }

#ifdef ENABLE_DEBUG
    /* take action to corrupt packet if we are in gremlin test mode */
    if (c->options.gremlin)
    {
        if (!ask_gremlin(c->options.gremlin))
        {
            c->c2.buf.len = 0;
        }
        corrupt_gremlin(&c->c2.buf, c->options.gremlin);
    }
#endif

    /* log incoming packet */
#ifdef LOG_RW
    if (c->c2.log_rw && c->c2.buf.len > 0)
    {
        fprintf(stderr, "R");
    }
#endif
    msg(D_LINK_RW, "%s READ [%d] from %s: %s",
        proto2ascii(lsi->proto, lsi->af, true),
        BLEN(&c->c2.buf),
        print_link_socket_actual(&c->c2.from, &gc),
        PROTO_DUMP(&c->c2.buf, &gc));

    /*
     * Good, non-zero length packet received.
     * Commence multi-stage processing of packet,
     * such as authenticate, decrypt, decompress.
     * If any stage fails, it sets buf.len to 0 or -1,
     * telling downstream stages to ignore the packet.
     */
    if (c->c2.buf.len > 0)
    {
        struct crypto_options *co = NULL;
        const uint8_t *ad_start = NULL;
        if (!link_socket_verify_incoming_addr(&c->c2.buf, lsi, &c->c2.from))
        {
            link_socket_bad_incoming_addr(&c->c2.buf, lsi, &c->c2.from);
        }

        if (c->c2.tls_multi)
        {
            /*
             * If tls_pre_decrypt returns true, it means the incoming
             * packet was a good TLS control channel packet.  If so, TLS code
             * will deal with the packet and set buf.len to 0 so downstream
             * stages ignore it.
             *
             * If the packet is a data channel packet, tls_pre_decrypt
             * will load crypto_options with the correct encryption key
             * and return false.
             */
            uint8_t opcode = *BPTR(&c->c2.buf) >> P_OPCODE_SHIFT;
            if (tls_pre_decrypt(c->c2.tls_multi, &c->c2.from, &c->c2.buf, &co,
                                floated, &ad_start))
            {
                /* Restore pre-NCP frame parameters */
                if (is_hard_reset(opcode, c->options.key_method))
                {
                    c->c2.frame = c->c2.frame_initial;
                }

                interval_action(&c->c2.tmp_int);

                /* reset packet received timer if TLS packet */
                if (c->options.ping_rec_timeout)
                {
                    event_timeout_reset(&c->c2.ping_rec_interval);
                }
            }
        }
        else
        {
            co = &c->c2.crypto_options;
        }
#if P2MP_SERVER
        /*
         * Drop non-TLS packet if client-connect script/plugin has not
         * yet succeeded.
         */
        if (c->c2.context_auth != CAS_SUCCEEDED)
        {
            c->c2.buf.len = 0;
        }
#endif

        /* authenticate and decrypt the incoming packet */
        decrypt_status = openvpn_decrypt(&c->c2.buf, c->c2.buffers->decrypt_buf,
                                         co, &c->c2.frame, ad_start);

        if (!decrypt_status && link_socket_connection_oriented(c->c2.link_socket))
        {
            /* decryption errors are fatal in TCP mode */
            register_signal(c, SIGUSR1, "decryption-error"); /* SOFT-SIGUSR1 -- decryption error in TCP mode */
            msg(D_STREAM_ERRORS, "Fatal decryption error (process_incoming_link), restarting");
        }
    }
    else
    {
        buf_reset(&c->c2.to_tun);
    }
    gc_free(&gc);

    return decrypt_status;
}

void
process_incoming_link_part2(struct context *c, struct link_socket_info *lsi, const uint8_t *orig_buf)
{
    if (c->c2.buf.len > 0)
    {
#ifdef ENABLE_FRAGMENT
        if (c->c2.fragment)
        {
            fragment_incoming(c->c2.fragment, &c->c2.buf, &c->c2.frame_fragment);
        }
#endif

#ifdef USE_COMP
        /* decompress the incoming packet */
        if (c->c2.comp_context)
        {
            (*c->c2.comp_context->alg.decompress)(&c->c2.buf, c->c2.buffers->decompress_buf, c->c2.comp_context, &c->c2.frame);
        }
#endif

#ifdef PACKET_TRUNCATION_CHECK
        /* if (c->c2.buf.len > 1) --c->c2.buf.len; */
        ipv4_packet_size_verify(BPTR(&c->c2.buf),
                                BLEN(&c->c2.buf),
                                TUNNEL_TYPE(c->c1.tuntap),
                                "POST_DECRYPT",
                                &c->c2.n_trunc_post_decrypt);
#endif

        /*
         * Set our "official" outgoing address, since
         * if buf.len is non-zero, we know the packet
         * authenticated.  In TLS mode we do nothing
         * because TLS mode takes care of source address
         * authentication.
         *
         * Also, update the persisted version of our packet-id.
         */
        if (!TLS_MODE(c))
        {
            link_socket_set_outgoing_addr(&c->c2.buf, lsi, &c->c2.from, NULL, c->c2.es);
        }

        /* reset packet received timer */
        if (c->options.ping_rec_timeout && c->c2.buf.len > 0)
        {
            event_timeout_reset(&c->c2.ping_rec_interval);
        }

        /* increment authenticated receive byte count */
        if (c->c2.buf.len > 0)
        {
            c->c2.link_read_bytes_auth += c->c2.buf.len;
            c->c2.max_recv_size_local = max_int(c->c2.original_recv_size, c->c2.max_recv_size_local);
        }

        /* Did we just receive an openvpn ping packet? */
        if (is_ping_msg(&c->c2.buf))
        {
            dmsg(D_PING, "RECEIVED PING PACKET");
            c->c2.buf.len = 0; /* drop packet */
        }

#ifdef ENABLE_OCC
        /* Did we just receive an OCC packet? */
        if (is_occ_msg(&c->c2.buf))
        {
            process_received_occ_msg(c);
        }
#endif

        buffer_turnover(orig_buf, &c->c2.to_tun, &c->c2.buf, &c->c2.buffers->read_link_buf);

        /* to_tun defined + unopened tuntap can cause deadlock */
        if (!tuntap_defined(c->c1.tuntap))
        {
            c->c2.to_tun.len = 0;
        }
    }
    else
    {
        buf_reset(&c->c2.to_tun);
    }
}

static void
process_incoming_link(struct context *c, struct link_socket *ls)
{
    perf_push(PERF_PROC_IN_LINK);

    struct link_socket_info *lsi = &ls->info;
    const uint8_t *orig_buf = c->c2.buf.data;

    process_incoming_link_part1(c, lsi, false);
    process_incoming_link_part2(c, lsi, orig_buf);

    perf_pop();
}

/*
 * Output: c->c2.buf
 */

void
read_incoming_tun(struct context *c)
{
    /*
     * Setup for read() call on TUN/TAP device.
     */
    /*ASSERT (!c->c2.to_link.len);*/

    perf_push(PERF_READ_IN_TUN);

    c->c2.buf = c->c2.buffers->read_tun_buf;
#ifdef TUN_PASS_BUFFER
    read_tun_buffered(c->c1.tuntap, &c->c2.buf, MAX_RW_SIZE_TUN(&c->c2.frame));
#else
    ASSERT(buf_init(&c->c2.buf, FRAME_HEADROOM(&c->c2.frame)));
    ASSERT(buf_safe(&c->c2.buf, MAX_RW_SIZE_TUN(&c->c2.frame)));
    c->c2.buf.len = read_tun(c->c1.tuntap, BPTR(&c->c2.buf), MAX_RW_SIZE_TUN(&c->c2.frame));
#endif

#ifdef PACKET_TRUNCATION_CHECK
    ipv4_packet_size_verify(BPTR(&c->c2.buf),
                            BLEN(&c->c2.buf),
                            TUNNEL_TYPE(c->c1.tuntap),
                            "READ_TUN",
                            &c->c2.n_trunc_tun_read);
#endif

    /* Was TUN/TAP interface stopped? */
    if (tuntap_stop(c->c2.buf.len))
    {
        register_signal(c, SIGTERM, "tun-stop");
        msg(M_INFO, "TUN/TAP interface has been stopped, exiting");
        perf_pop();
        return;
    }

    /* Was TUN/TAP I/O operation aborted? */
    if (tuntap_abort(c->c2.buf.len))
    {
        register_signal(c, SIGHUP, "tun-abort");
        c->persist.restart_sleep_seconds = 10;
        msg(M_INFO, "TUN/TAP I/O operation aborted, restarting");
        perf_pop();
        return;
    }

    /* Check the status return from read() */
    check_status(c->c2.buf.len, "read from TUN/TAP", NULL, c->c1.tuntap);

    perf_pop();
}

/**
 * Drops UDP packets which OS decided to route via tun.
 *
 * On Windows and OS X when netwotk adapter is disabled or
 * disconnected, platform starts to use tun as external interface.
 * When packet is sent to tun, it comes to openvpn, encapsulated
 * and sent to routing table, which sends it again to tun.
 */
static void
drop_if_recursive_routing(struct context *c, struct buffer *buf)
{
    bool drop = false;
    struct openvpn_sockaddr tun_sa;
    int ip_hdr_offset = 0;

    if (c->c2.to_link_addr == NULL) /* no remote addr known */
    {
        return;
    }

    tun_sa = c->c2.to_link_addr->dest;

    int proto_ver = get_tun_ip_ver(TUNNEL_TYPE(c->c1.tuntap), &c->c2.buf, &ip_hdr_offset);

    if (proto_ver == 4)
    {
        const struct openvpn_iphdr *pip;

        /* make sure we got whole IP header */
        if (BLEN(buf) < ((int) sizeof(struct openvpn_iphdr) + ip_hdr_offset))
        {
            return;
        }

        /* skip ipv4 packets for ipv6 tun */
        if (tun_sa.addr.sa.sa_family != AF_INET)
        {
            return;
        }

        pip = (struct openvpn_iphdr *) (BPTR(buf) + ip_hdr_offset);

        /* drop packets with same dest addr as gateway */
        if (tun_sa.addr.in4.sin_addr.s_addr == pip->daddr)
        {
            drop = true;
        }
    }
    else if (proto_ver == 6)
    {
        const struct openvpn_ipv6hdr *pip6;

        /* make sure we got whole IPv6 header */
        if (BLEN(buf) < ((int) sizeof(struct openvpn_ipv6hdr) + ip_hdr_offset))
        {
            return;
        }

        /* skip ipv6 packets for ipv4 tun */
        if (tun_sa.addr.sa.sa_family != AF_INET6)
        {
            return;
        }

        /* drop packets with same dest addr as gateway */
        pip6 = (struct openvpn_ipv6hdr *) (BPTR(buf) + ip_hdr_offset);
        if (IN6_ARE_ADDR_EQUAL(&tun_sa.addr.in6.sin6_addr, &pip6->daddr))
        {
            drop = true;
        }
    }

    if (drop)
    {
        struct gc_arena gc = gc_new();

        c->c2.buf.len = 0;

        msg(D_LOW, "Recursive routing detected, drop tun packet to %s",
            print_link_socket_actual(c->c2.to_link_addr, &gc));
        gc_free(&gc);
    }
}

/*
 * Input:  c->c2.buf
 * Output: c->c2.to_link
 */

void
process_incoming_tun(struct context *c)
{
    struct gc_arena gc = gc_new();

    perf_push(PERF_PROC_IN_TUN);

    if (c->c2.buf.len > 0)
    {
        c->c2.tun_read_bytes += c->c2.buf.len;
    }

#ifdef LOG_RW
    if (c->c2.log_rw && c->c2.buf.len > 0)
    {
        fprintf(stderr, "r");
    }
#endif

    /* Show packet content */
    dmsg(D_TUN_RW, "TUN READ [%d]", BLEN(&c->c2.buf));

    if (c->c2.buf.len > 0)
    {
        if ((c->options.mode == MODE_POINT_TO_POINT) && (!c->options.allow_recursive_routing))
        {
            drop_if_recursive_routing(c, &c->c2.buf);
        }
        /*
         * The --passtos and --mssfix options require
         * us to examine the IP header (IPv4 or IPv6).
         */
        process_ip_header(c, PIPV4_PASSTOS|PIP_MSSFIX|PIPV4_CLIENT_NAT, &c->c2.buf);

#ifdef PACKET_TRUNCATION_CHECK
        /* if (c->c2.buf.len > 1) --c->c2.buf.len; */
        ipv4_packet_size_verify(BPTR(&c->c2.buf),
                                BLEN(&c->c2.buf),
                                TUNNEL_TYPE(c->c1.tuntap),
                                "PRE_ENCRYPT",
                                &c->c2.n_trunc_pre_encrypt);
#endif

        encrypt_sign(c, true);
    }
    else
    {
        buf_reset(&c->c2.to_link);
    }
    perf_pop();
    gc_free(&gc);
}

void
process_ip_header(struct context *c, unsigned int flags, struct buffer *buf)
{
    if (!c->options.ce.mssfix)
    {
        flags &= ~PIP_MSSFIX;
    }
#if PASSTOS_CAPABILITY
    if (!c->options.passtos)
    {
        flags &= ~PIPV4_PASSTOS;
    }
#endif
    if (!c->options.client_nat)
    {
        flags &= ~PIPV4_CLIENT_NAT;
    }
    if (!c->options.route_gateway_via_dhcp)
    {
        flags &= ~PIPV4_EXTRACT_DHCP_ROUTER;
    }

    if (buf->len > 0)
    {
        /*
         * The --passtos and --mssfix options require
         * us to examine the IPv4 header.
         */

        if (flags & (PIP_MSSFIX
#if PASSTOS_CAPABILITY
                     | PIPV4_PASSTOS
#endif
                     | PIPV4_CLIENT_NAT
                     ))
        {
            struct buffer ipbuf = *buf;
            if (is_ipv4(TUNNEL_TYPE(c->c1.tuntap), &ipbuf))
            {
#if PASSTOS_CAPABILITY
                /* extract TOS from IP header */
                if (flags & PIPV4_PASSTOS)
                {
                    link_socket_extract_tos(c->c2.link_socket, &ipbuf);
                }
#endif

                /* possibly alter the TCP MSS */
                if (flags & PIP_MSSFIX)
                {
                    mss_fixup_ipv4(&ipbuf, MTU_TO_MSS(TUN_MTU_SIZE_DYNAMIC(&c->c2.frame)));
                }

                /* possibly do NAT on packet */
                if ((flags & PIPV4_CLIENT_NAT) && c->options.client_nat)
                {
                    const int direction = (flags & PIPV4_OUTGOING) ? CN_INCOMING : CN_OUTGOING;
                    client_nat_transform(c->options.client_nat, &ipbuf, direction);
                }
                /* possibly extract a DHCP router message */
                if (flags & PIPV4_EXTRACT_DHCP_ROUTER)
                {
                    const in_addr_t dhcp_router = dhcp_extract_router_msg(&ipbuf);
                    if (dhcp_router)
                    {
                        route_list_add_vpn_gateway(c->c1.route_list, c->c2.es, dhcp_router);
                    }
                }
            }
            else if (is_ipv6(TUNNEL_TYPE(c->c1.tuntap), &ipbuf))
            {
                /* possibly alter the TCP MSS */
                if (flags & PIP_MSSFIX)
                {
                    mss_fixup_ipv6(&ipbuf, MTU_TO_MSS(TUN_MTU_SIZE_DYNAMIC(&c->c2.frame)));
                }
            }
        }
    }
}

/*
 * Input: c->c2.to_link
 */

void
process_outgoing_link(struct context *c, struct link_socket *ls)
{
    struct gc_arena gc = gc_new();
    int error_code = 0;

    perf_push(PERF_PROC_OUT_LINK);

    if (c->c2.to_link.len > 0 && c->c2.to_link.len <= EXPANDED_SIZE(&c->c2.frame))
    {
        /*
         * Setup for call to send/sendto which will send
         * packet to remote over the TCP/UDP port.
         */
        int size = 0;
        ASSERT(link_socket_actual_defined(c->c2.to_link_addr));

#ifdef ENABLE_DEBUG
        /* In gremlin-test mode, we may choose to drop this packet */
        if (!c->options.gremlin || ask_gremlin(c->options.gremlin))
#endif
        {
            /*
             * Let the traffic shaper know how many bytes
             * we wrote.
             */
#ifdef ENABLE_FEATURE_SHAPER
            if (c->options.shaper)
            {
                shaper_wrote_bytes(&c->c2.shaper, BLEN(&c->c2.to_link)
                                   + datagram_overhead(c->options.ce.proto));
            }
#endif
            /*
             * Let the pinger know that we sent a packet.
             */
            if (c->options.ping_send_timeout)
            {
                event_timeout_reset(&c->c2.ping_send_interval);
            }

#if PASSTOS_CAPABILITY
            /* Set TOS */
            link_socket_set_tos(ls);
#endif

            /* Log packet send */
#ifdef LOG_RW
            if (c->c2.log_rw)
            {
                fprintf(stderr, "W");
            }
#endif
            msg(D_LINK_RW, "%s WRITE [%d] to %s: %s",
                proto2ascii(ls->info.proto, ls->info.af, true),
                BLEN(&c->c2.to_link),
                print_link_socket_actual(c->c2.to_link_addr, &gc),
                PROTO_DUMP(&c->c2.to_link, &gc));

            /* Packet send complexified by possible Socks5 usage */
            {
                struct link_socket_actual *to_addr = c->c2.to_link_addr;
                int size_delta = 0;

                /* If Socks5 over UDP, prepend header */
                socks_preprocess_outgoing_link(c, ls, &to_addr, &size_delta);

                /* Send packet */
                size = link_socket_write(ls,
                                         &c->c2.to_link,
                                         to_addr);

                /* Undo effect of prepend */
                link_socket_write_post_size_adjust(&size, size_delta, &c->c2.to_link);
            }

            if (size > 0)
            {
                c->c2.max_send_size_local = max_int(size, c->c2.max_send_size_local);
                c->c2.link_write_bytes += size;
                link_write_bytes_global += size;
#ifdef ENABLE_MEMSTATS
                if (mmap_stats)
                {
                    mmap_stats->link_write_bytes = link_write_bytes_global;
                }
#endif
#ifdef ENABLE_MANAGEMENT
                if (management)
                {
                    management_bytes_out(management, size);
#ifdef MANAGEMENT_DEF_AUTH
                    management_bytes_server(management, &c->c2.link_read_bytes, &c->c2.link_write_bytes, &c->c2.mda_context);
#endif
                }
#endif
            }
        }

        /* Check return status */
        error_code = openvpn_errno();
        check_status(size, "write", ls, NULL);

        if (size > 0)
        {
            /* Did we write a different size packet than we intended? */
            if (size != BLEN(&c->c2.to_link))
            {
                msg(D_LINK_ERRORS,
                    "TCP/UDP packet was truncated/expanded on write to %s (tried=%d,actual=%d)",
                    print_link_socket_actual(c->c2.to_link_addr, &gc),
                    BLEN(&c->c2.to_link),
                    size);
            }
        }

        /* if not a ping/control message, indicate activity regarding --inactive parameter */
        if (c->c2.buf.len > 0)
        {
            register_activity(c, size);
        }

        /* for unreachable network and "connecting" state switch to the next host */
        if (size < 0 && ENETUNREACH == error_code && c->c2.tls_multi
            && !tls_initial_packet_received(c->c2.tls_multi) && c->options.mode == MODE_POINT_TO_POINT)
        {
            msg(M_INFO, "Network unreachable, restarting");
            register_signal(c, SIGUSR1, "network-unreachable");
        }
    }
    else
    {
        if (c->c2.to_link.len > 0)
        {
            msg(D_LINK_ERRORS, "TCP/UDP packet too large on write to %s (tried=%d,max=%d)",
                print_link_socket_actual(c->c2.to_link_addr, &gc),
                c->c2.to_link.len,
                EXPANDED_SIZE(&c->c2.frame));
        }
    }

    buf_reset(&c->c2.to_link);

    perf_pop();
    gc_free(&gc);
}

/*
 * Input: c->c2.to_tun
 */

void
process_outgoing_tun(struct context *c)
{
    struct gc_arena gc = gc_new();

    /*
     * Set up for write() call to TUN/TAP
     * device.
     */
    if (c->c2.to_tun.len <= 0)
    {
        return;
    }

    perf_push(PERF_PROC_OUT_TUN);

    /*
     * The --mssfix option requires
     * us to examine the IP header (IPv4 or IPv6).
     */
    process_ip_header(c, PIP_MSSFIX|PIPV4_EXTRACT_DHCP_ROUTER|PIPV4_CLIENT_NAT|PIPV4_OUTGOING, &c->c2.to_tun);

    if (c->c2.to_tun.len <= MAX_RW_SIZE_TUN(&c->c2.frame))
    {
        /*
         * Write to TUN/TAP device.
         */
        int size;

#ifdef LOG_RW
        if (c->c2.log_rw)
        {
            fprintf(stderr, "w");
        }
#endif
        dmsg(D_TUN_RW, "TUN WRITE [%d]", BLEN(&c->c2.to_tun));

#ifdef PACKET_TRUNCATION_CHECK
        ipv4_packet_size_verify(BPTR(&c->c2.to_tun),
                                BLEN(&c->c2.to_tun),
                                TUNNEL_TYPE(c->c1.tuntap),
                                "WRITE_TUN",
                                &c->c2.n_trunc_tun_write);
#endif

#ifdef TUN_PASS_BUFFER
        size = write_tun_buffered(c->c1.tuntap, &c->c2.to_tun);
#else
        size = write_tun(c->c1.tuntap, BPTR(&c->c2.to_tun), BLEN(&c->c2.to_tun));
#endif

        if (size > 0)
        {
            c->c2.tun_write_bytes += size;
        }
        check_status(size, "write to TUN/TAP", NULL, c->c1.tuntap);

        /* check written packet size */
        if (size > 0)
        {
            /* Did we write a different size packet than we intended? */
            if (size != BLEN(&c->c2.to_tun))
            {
                msg(D_LINK_ERRORS,
                    "TUN/TAP packet was destructively fragmented on write to %s (tried=%d,actual=%d)",
                    c->c1.tuntap->actual_name,
                    BLEN(&c->c2.to_tun),
                    size);
            }

            /* indicate activity regarding --inactive parameter */
            register_activity(c, size);
        }
    }
    else
    {
        /*
         * This should never happen, probably indicates some kind
         * of MTU mismatch.
         */
        msg(D_LINK_ERRORS, "tun packet too large on write (tried=%d,max=%d)",
            c->c2.to_tun.len,
            MAX_RW_SIZE_TUN(&c->c2.frame));
    }

    buf_reset(&c->c2.to_tun);

    perf_pop();
    gc_free(&gc);
}

void
pre_select(struct context *c)
{
    /* make sure current time (now) is updated on function entry */

    /*
     * Start with an effectively infinite timeout, then let it
     * reduce to a timeout that reflects the component which
     * needs the earliest service.
     */
    c->c2.timeval.tv_sec = BIG_TIMEOUT;
    c->c2.timeval.tv_usec = 0;

#if defined(_WIN32)
    if (check_debug_level(D_TAP_WIN_DEBUG))
    {
        c->c2.timeval.tv_sec = 1;
        if (tuntap_defined(c->c1.tuntap))
        {
            tun_show_debug(c->c1.tuntap);
        }
    }
#endif

    /* check coarse timers? */
    check_coarse_timers(c);
    if (c->sig->signal_received)
    {
        return;
    }

    /* Does TLS need service? */
    check_tls(c);

    /* In certain cases, TLS errors will require a restart */
    check_tls_errors(c);
    if (c->sig->signal_received)
    {
        return;
    }

    /* check for incoming configuration info on the control channel */
    check_incoming_control_channel(c);

#ifdef ENABLE_OCC
    /* Should we send an OCC message? */
    check_send_occ_msg(c);
#endif

#ifdef ENABLE_FRAGMENT
    /* Should we deliver a datagram fragment to remote? */
    check_fragment(c);
#endif

    /* Update random component of timeout */
    check_timeout_random_component(c);
}

/*
 * Wait for I/O events.  Used for both TCP & UDP sockets
 * in point-to-point mode and for UDP sockets in
 * point-to-multipoint mode.
 */

void
io_wait_dowork(struct context *c, const unsigned int flags)
{
    unsigned int socket = 0;
    unsigned int tuntap = 0;
    struct event_set_return esr[4];

    /* These shifts all depend on EVENT_READ and EVENT_WRITE */
    static uintptr_t socket_shift = 0;   /* depends on SOCKET_READ and SOCKET_WRITE */
    static uintptr_t tun_shift = 2;      /* depends on TUN_READ and TUN_WRITE */
    static uintptr_t err_shift = 4;      /* depends on ES_ERROR */
#ifdef ENABLE_MANAGEMENT
    static uintptr_t management_shift = 6; /* depends on MANAGEMENT_READ and MANAGEMENT_WRITE */
#endif
#ifdef ENABLE_ASYNC_PUSH
    static int file_shift = 8;     /* listening inotify events */
#endif

    /*
     * Decide what kind of events we want to wait for.
     */
    event_reset(c->c2.event_set);

    /*
     * On win32 we use the keyboard or an event object as a source
     * of asynchronous signals.
     */
    if (flags & IOW_WAIT_SIGNAL)
    {
        wait_signal(c->c2.event_set, (void *)err_shift);
    }

    /*
     * If outgoing data (for TCP/UDP port) pending, wait for ready-to-send
     * status from TCP/UDP port. Otherwise, wait for incoming data on
     * TUN/TAP device.
     */
    if (flags & IOW_TO_LINK)
    {
        if (flags & IOW_SHAPER)
        {
            /*
             * If sending this packet would put us over our traffic shaping
             * quota, don't send -- instead compute the delay we must wait
             * until it will be OK to send the packet.
             */
#ifdef ENABLE_FEATURE_SHAPER
            int delay = 0;

            /* set traffic shaping delay in microseconds */
            if (c->options.shaper)
            {
                delay = max_int(delay, shaper_delay(&c->c2.shaper));
            }

            if (delay < 1000)
            {
                socket |= EVENT_WRITE;
            }
            else
            {
                shaper_soonest_event(&c->c2.timeval, delay);
            }
#else /* ENABLE_FEATURE_SHAPER */
            socket |= EVENT_WRITE;
#endif /* ENABLE_FEATURE_SHAPER */
        }
        else
        {
            socket |= EVENT_WRITE;
        }
    }
    else if (!((flags & IOW_FRAG) && TO_LINK_FRAG(c)))
    {
        if (flags & IOW_READ_TUN)
        {
            tuntap |= EVENT_READ;
        }
    }

    /*
     * If outgoing data (for TUN/TAP device) pending, wait for ready-to-send status
     * from device.  Otherwise, wait for incoming data on TCP/UDP port.
     */
    if (flags & IOW_TO_TUN)
    {
        tuntap |= EVENT_WRITE;
    }
    else
    {
        if (flags & IOW_READ_LINK)
        {
            socket |= EVENT_READ;
        }
    }

    /*
     * outgoing bcast buffer waiting to be sent?
     */
    if (flags & IOW_MBUF)
    {
        socket |= EVENT_WRITE;
    }

    /*
     * Force wait on TUN input, even if also waiting on TCP/UDP output
     */
    if (flags & IOW_READ_TUN_FORCE)
    {
        tuntap |= EVENT_READ;
    }

    /*
     * Configure event wait based on socket, tuntap flags.
     */
    socket_set(c->c2.link_socket, c->c2.event_set, socket, (void *)socket_shift, NULL);
    tun_set(c->c1.tuntap, c->c2.event_set, tuntap, (void *)tun_shift, NULL);

#ifdef ENABLE_MANAGEMENT
    if (management)
    {
        management_socket_set(management, c->c2.event_set, (void *)management_shift, NULL);
    }
#endif

#ifdef ENABLE_ASYNC_PUSH
    /* arm inotify watcher */
    if (c->options.mode == MODE_SERVER)
    {
        event_ctl(c->c2.event_set, c->c2.inotify_fd, EVENT_READ, (void *)file_shift);
    }
#endif

    /*
     * Possible scenarios:
     *  (1) tcp/udp port has data available to read
     *  (2) tcp/udp port is ready to accept more data to write
     *  (3) tun dev has data available to read
     *  (4) tun dev is ready to accept more data to write
     *  (5) we received a signal (handler sets signal_received)
     *  (6) timeout (tv) expired
     */

    c->c2.event_set_status = ES_ERROR;

    if (!c->sig->signal_received)
    {
        if (!(flags & IOW_CHECK_RESIDUAL) || !socket_read_residual(c->c2.link_socket))
        {
            int status;

#ifdef ENABLE_DEBUG
            if (check_debug_level(D_EVENT_WAIT))
            {
                show_wait_status(c);
            }
#endif

            /*
             * Wait for something to happen.
             */
            status = event_wait(c->c2.event_set, &c->c2.timeval, esr, SIZE(esr));

            check_status(status, "event_wait", NULL, NULL);

            if (status > 0)
            {
                int i;
                c->c2.event_set_status = 0;
                for (i = 0; i < status; ++i)
                {
                    const struct event_set_return *e = &esr[i];
                    c->c2.event_set_status |= ((e->rwflags & 3) << (uintptr_t)e->arg);
                }
            }
            else if (status == 0)
            {
                c->c2.event_set_status = ES_TIMEOUT;
            }
        }
        else
        {
            c->c2.event_set_status = SOCKET_READ;
        }
    }

    /* 'now' should always be a reasonably up-to-date timestamp */
    update_time();

    /* set signal_received if a signal was received */
    if (c->c2.event_set_status & ES_ERROR)
    {
        get_signal(&c->sig->signal_received);
    }

    dmsg(D_EVENT_WAIT, "I/O WAIT status=0x%04x", c->c2.event_set_status);
}

void
process_io(struct context *c, struct link_socket *ls)
{
    const unsigned int status = c->c2.event_set_status;

#ifdef ENABLE_MANAGEMENT
    if (status & (MANAGEMENT_READ|MANAGEMENT_WRITE))
    {
        ASSERT(management);
        management_io(management);
    }
#endif

    /* TCP/UDP port ready to accept write */
    if (status & SOCKET_WRITE)
    {
        process_outgoing_link(c, ls);
    }
    /* TUN device ready to accept write */
    else if (status & TUN_WRITE)
    {
        process_outgoing_tun(c);
    }
    /* Incoming data on TCP/UDP port */
    else if (status & SOCKET_READ)
    {
        read_incoming_link(c, ls);
        if (!IS_SIG(c))
        {
            process_incoming_link(c, ls);
        }
    }
    /* Incoming data on TUN device */
    else if (status & TUN_READ)
    {
        read_incoming_tun(c);
        if (!IS_SIG(c))
        {
            process_incoming_tun(c);
        }
    }
}
