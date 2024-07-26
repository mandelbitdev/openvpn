/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2025 OpenVPN Inc <sales@openvpn.net>
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

#ifndef HAPROXY_PROTOCOL_H
#define HAPROXY_PROTOCOL_H

#include "buffer.h"
#include "openvpn.h"
#include "socket.h"

#include <stdbool.h>
#include <stdint.h>

/* https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt */

#define HAPROXY_PROTOCOL_V1_SIG          "PROXY"
#define HAPROXY_PROTOCOL_V1_SIG_LEN      5
#define HAPROXY_PROTOCOL_V1_MIN_HDR_LEN  8
#define HAPROXY_PROTOCOL_V1_LINE_MAX_LEN 108

#define HAPROXY_PROTOCOL_V2_SIG         "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A"
#define HAPROXY_PROTOCOL_V2_SIG_LEN     12
#define HAPROXY_PROTOCOL_V2_MIN_HDR_LEN 16

#define HAPROXY_PROTOCOL_V2_VER_MASK 0xF0
#define HAPROXY_PROTOCOL_V2_VER      (0x2 << 4)

#define HAPROXY_PROTOCOL_V2_CMD_MASK  0x0F
#define HAPROXY_PROTOCOL_V2_LOCAL_CMD (0x0 << 0)
#define HAPROXY_PROTOCOL_V2_PROXY_CMD (0x1 << 0)

#define HAPROXY_PROTOCOL_V2_AF_MASK   0xF0
#define HAPROXY_PROTOCOL_V2_AF_UNSPEC (0x0 << 4)
#define HAPROXY_PROTOCOL_V2_AF_INET   (0x1 << 4)
#define HAPROXY_PROTOCOL_V2_AF_INET6  (0x2 << 4)
#define HAPROXY_PROTOCOL_V2_AF_UNIX   (0x3 << 4)

#define HAPROXY_PROTOCOL_V2_TP_MASK   0x0F
#define HAPROXY_PROTOCOL_V2_TP_UNSPEC (0x0 << 0)
#define HAPROXY_PROTOCOL_V2_TP_STREAM (0x1 << 0)
#define HAPROXY_PROTOCOL_V2_TP_DGRAM  (0x2 << 0)

#define HAPROXY_PROTOCOL_TLV_TYPE_ALPN            0x01
#define HAPROXY_PROTOCOL_TLV_TYPE_AUTHORITY       0x02
#define HAPROXY_PROTOCOL_TLV_TYPE_CRC32C          0x03
#define HAPROXY_PROTOCOL_TLV_TYPE_NOOP            0x04
#define HAPROXY_PROTOCOL_TLV_TYPE_UNIQUE_ID       0x05
#define HAPROXY_PROTOCOL_TLV_TYPE_SSL             0x20
#define HAPROXY_PROTOCOL_TLV_SUBTYPE_SSL_VERSION  0x21
#define HAPROXY_PROTOCOL_TLV_SUBTYPE_SSL_CN       0x22
#define HAPROXY_PROTOCOL_TLV_SUBTYPE_SSL_CIPHER   0x23
#define HAPROXY_PROTOCOL_TLV_SUBTYPE_SSL_SIG_ALG  0x24
#define HAPROXY_PROTOCOL_TLV_SUBTYPE_SSL_KEY_ALG  0x25
#define HAPROXY_PROTOCOL_TLV_TYPE_NETNS           0x30

#define HAPROXY_PROTOCOL_V2_CLIENT_SSL          0x01
#define HAPROXY_PROTOCOL_V2_CLIENT_CERT_CONN    0x02
#define HAPROXY_PROTOCOL_V2_CLIENT_CERT_SESS    0x04

#define HAPROXY_PROTOCOL_V2_TLV_UNIQUE_ID_MAX_LEN 128

typedef enum
{
    HAPROXY_PROTOCOL_VERSION_INVALID = -1,

    HAPROXY_PROTOCOL_VERSION_UNKNOWN = 0,
    HAPROXY_PROTOCOL_VERSION_1,
    HAPROXY_PROTOCOL_VERSION_2,
} haproxy_protocol_version_t;

struct haproxy_protocol_tlv
{
    uint8_t type;
    uint8_t length_hi;
    uint8_t length_lo;
    uint8_t value[0];
};

#pragma pack(push, 1)
struct haproxy_protocol_tlv_ssl
{
    uint8_t client;
    uint32_t verify;
} __attribute__((packed));
#pragma pack(pop)

#pragma pack(push, 1)
typedef union
{
    struct
    {
        char line[HAPROXY_PROTOCOL_V1_LINE_MAX_LEN];
    } v1;
    struct
    {
        uint8_t sig[HAPROXY_PROTOCOL_V2_SIG_LEN];
        uint8_t ver_cmd;
        uint8_t fam;
        uint16_t len;
        union
        {
            struct
            {
                uint32_t src_addr;
                uint32_t dst_addr;
                uint16_t src_port;
                uint16_t dst_port;
            } ip4;
            struct
            {
                uint8_t src_addr[16];
                uint8_t dst_addr[16];
                uint16_t src_port;
                uint16_t dst_port;
            } ip6;
            struct
            {
                uint8_t src_addr[108];
                uint8_t dst_addr[108];
            } unx;
        } addr;
    } v2;
} __attribute__((packed)) haproxy_protocol_header_t;
#pragma pack(pop)

struct haproxy_protocol_tlv_info
{
    struct gc_arena gc;

    char *alpn;
    char *authority;
    uint8_t unique_id[HAPROXY_PROTOCOL_V2_TLV_UNIQUE_ID_MAX_LEN + 1];
    uint16_t unique_id_len;
    uint8_t ssl_client;
    uint32_t ssl_verify;
    char *ssl_version;
    char *ssl_cn;
    char *ssl_cipher;
    char *ssl_sig_alg;
    char *ssl_key_alg;
    char *netns;
};

struct haproxy_protocol_info
{
    haproxy_protocol_version_t version;
    int sock_type;
    struct openvpn_sockaddr src;
    struct openvpn_sockaddr dst;

    struct haproxy_protocol_tlv_info tlv;
};

/*
 * Check if the buffer contains an PROXY protocol header and return the version.
 *
 * @param buf - The buffer to check.
 * @param buf_len - The length of the buffer.
 *
 * @return - The PROXY protocol version or HAPROXY_PROTOCOL_VERSION_INVALID if
 *          the buffer does not contain a valid PROXY protocol header.
 */
haproxy_protocol_version_t
haproxy_protocol_version(const uint8_t *buf, int buf_len);

/*
 * Get the length of the PROXY protocol header.
 * This function does not check if the header is fully contained in the buffer
 * therefore it is the caller's responsibility to perform this check.
 *
 * @param buf - The buffer to check.
 * @param buf_len - The length of the buffer.
 * @param version - The PROXY protocol version.
 *
 * @return - The length of the header or -1 if the header is partial or invalid.
 */
int
haproxy_protocol_header_len(const uint8_t *buf, int len, haproxy_protocol_version_t version);

/*
 * Parse the PROXY protocol header.
 *
 * @param hpi - The proxy protocol info structure to store the parsed data.
 * @param buf - The header to parse.
 * @param buf_len - The length of the header.
 *
 * @return - true if the header was successfully parsed.
 */
bool
haproxy_protocol_parse(struct haproxy_protocol_info *hpi, const uint8_t *buf, int buf_len);

/*
 * Free the allocated memory.
 *
 * @param hpi - The proxy protocol info structure.
 */
void
haproxy_protocol_reset(struct haproxy_protocol_info *hpi);

#endif /* HAPROXY_PROTOCOL_H */
