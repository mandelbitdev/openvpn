/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2024 OpenVPN Inc <sales@openvpn.net>
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

#ifndef PROXY_PROTOCOL_H
#define PROXY_PROTOCOL_H

#include "buffer.h"
#include "openvpn.h"
#include "socket.h"

#include <stdbool.h>
#include <stdint.h>

/* https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt */

#define PROXY_PROTOCOL_V1_SIG          "PROXY"
#define PROXY_PROTOCOL_V1_SIG_LEN      5
#define PROXY_PROTOCOL_V1_MIN_HDR_LEN  8
#define PROXY_PROTOCOL_V1_LINE_MAX_LEN 108

#define PROXY_PROTOCOL_V2_SIG         "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A"
#define PROXY_PROTOCOL_V2_SIG_LEN     12
#define PROXY_PROTOCOL_V2_MIN_HDR_LEN 16

#define PROXY_PROTOCOL_V2_VER_MASK 0xF0
#define PROXY_PROTOCOL_V2_VER      (0x2 << 4)

#define PROXY_PROTOCOL_V2_CMD_MASK  0x0F
#define PROXY_PROTOCOL_V2_LOCAL_CMD (0x0 << 0)
#define PROXY_PROTOCOL_V2_PROXY_CMD (0x1 << 0)

#define PROXY_PROTOCOL_V2_AF_MASK   0xF0
#define PROXY_PROTOCOL_V2_AF_UNSPEC (0x0 << 4)
#define PROXY_PROTOCOL_V2_AF_INET   (0x1 << 4)
#define PROXY_PROTOCOL_V2_AF_INET6  (0x2 << 4)
#define PROXY_PROTOCOL_V2_AF_UNIX   (0x3 << 4)

#define PROXY_PROTOCOL_V2_TP_MASK   0x0F
#define PROXY_PROTOCOL_V2_TP_UNSPEC (0x0 << 0)
#define PROXY_PROTOCOL_V2_TP_STREAM (0x1 << 0)
#define PROXY_PROTOCOL_V2_TP_DGRAM  (0x2 << 0)

#define PROXY_PROTOCOL_TLV_TYPE_ALPN            0x01
#define PROXY_PROTOCOL_TLV_TYPE_AUTHORITY       0x02
#define PROXY_PROTOCOL_TLV_TYPE_CRC32C          0x03
#define PROXY_PROTOCOL_TLV_TYPE_NOOP            0x04
#define PROXY_PROTOCOL_TLV_TYPE_UNIQUE_ID       0x05
#define PROXY_PROTOCOL_TLV_TYPE_SSL             0x20
#define PROXY_PROTOCOL_TLV_SUBTYPE_SSL_VERSION  0x21
#define PROXY_PROTOCOL_TLV_SUBTYPE_SSL_CN       0x22
#define PROXY_PROTOCOL_TLV_SUBTYPE_SSL_CIPHER   0x23
#define PROXY_PROTOCOL_TLV_SUBTYPE_SSL_SIG_ALG  0x24
#define PROXY_PROTOCOL_TLV_SUBTYPE_SSL_KEY_ALG  0x25
#define PROXY_PROTOCOL_TLV_TYPE_NETNS           0x30

#define PROXY_PROTOCOL_V2_CLIENT_SSL          0x01
#define PROXY_PROTOCOL_V2_CLIENT_CERT_CONN    0x02
#define PROXY_PROTOCOL_V2_CLIENT_CERT_SESS    0x04

#define PROXY_PROTOCOL_V2_TLV_UNIQUE_ID_MAX_LEN 128

typedef enum
{
    PROXY_PROTOCOL_VERSION_INVALID = -1,

    PROXY_PROTOCOL_VERSION_UNKNOWN = 0,
    PROXY_PROTOCOL_VERSION_1,
    PROXY_PROTOCOL_VERSION_2,
} proxy_protocol_version_t;

struct proxy_protocol_tlv
{
    uint8_t type;
    uint8_t length_hi;
    uint8_t length_lo;
    uint8_t value[0];
};

#pragma pack(push, 1)
struct proxy_protocol_tlv_ssl
{
    uint8_t client;
    uint32_t verify;
} __attribute__((packed));
#pragma pack(pop)

/* HAProxy PROXY protocol header */
typedef union
{
    struct
    {
        char line[PROXY_PROTOCOL_V1_LINE_MAX_LEN];
    } v1;
    struct
    {
        uint8_t sig[PROXY_PROTOCOL_V2_SIG_LEN];
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
} proxy_protocol_header_t;

struct proxy_protocol_info
{
    struct gc_arena gc;

    proxy_protocol_version_t version;
    int sock_type;
    struct openvpn_sockaddr src;
    struct openvpn_sockaddr dst;

    /* data extracted from TLVs */
    char *alpn;
    char *authority;

    uint8_t unique_id[PROXY_PROTOCOL_V2_TLV_UNIQUE_ID_MAX_LEN + 1];
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

/*
 * Check if the buffer contains a PROXY protocol header and return the version.
 *
 * @param buf - The buffer to check.
 * @param buf_len - The length of the buffer.
 *
 * @return - The PROXY protocol version or PROXY_PROTOCOL_VERSION_INVALID if
 *          the buffer does not contain a valid PROXY protocol header.
 */
proxy_protocol_version_t
proxy_protocol_version(const uint8_t *buf, int buf_len);

/*
 * Get the length of the PROXY protocol header.
 *
 * @param buf - The buffer to check.
 * @param buf_len - The length of the buffer.
 * @param version - The PROXY protocol version.
 *
 * @return - The length of the header or -1 if the header is partial or invalid.
 */
int
proxy_protocol_header_len(const uint8_t *buf, int len,
                          proxy_protocol_version_t version);

/*
 * Parse the PROXY protocol header.
 *
 * @param ppi - The proxy protocol info structure to store the parsed data.
 * @param buf - The buffer containing the header.
 * @param version - The version of the PROXY protocol.
 *
 * @return - true if the header was successfully parsed.
 */
bool
proxy_protocol_parse(struct proxy_protocol_info *ppi, const struct buffer *buf);

/*
 * Free the allocated memory.
 *
 * @param ppi - The proxy protocol info structure.
 */
void
proxy_protocol_free(struct proxy_protocol_info *ppi);

#endif /* PROXY_PROTOCOL_H */
