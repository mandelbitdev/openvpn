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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"

#include "error.h"
#include "haproxy_protocol.h"

#define HAPROXY_PROTOCOL_V1_MAX_WORDS 6
#define HAPROXY_PROTOCOL_V1_MAX_WORD_LEN 40

typedef enum
{
    HAPROXY_PROTOCOL_PARSING_STATE_INVALID = -1,
    HAPROXY_PROTOCOL_PARSING_STATE_OK = 0,
    HAPROXY_PROTOCOL_PARSING_STATE_IGNORE = 1,
} haproxy_protocol_parsing_state_t;

static const size_t HAPROXY_PROTOCOL_V2_ADDR_LEN_IPV4 = 12;
static const size_t HAPROXY_PROTOCOL_V2_ADDR_LEN_IPV6 = 36;
static const size_t HAPROXY_PROTOCOL_V2_ADDR_LEN_UNIX = 216;

static haproxy_protocol_header_t *header = NULL;
static uint16_t header_len = 0;
static haproxy_protocol_parsing_state_t parsing_state = HAPROXY_PROTOCOL_PARSING_STATE_OK;

haproxy_protocol_version_t
haproxy_protocol_version(const uint8_t *buf, const int buf_len)
{
    if (buf_len >= HAPROXY_PROTOCOL_V2_MIN_HDR_LEN
        && memcmp(buf, HAPROXY_PROTOCOL_V2_SIG, HAPROXY_PROTOCOL_V2_SIG_LEN) == 0)
    {
        return HAPROXY_PROTOCOL_VERSION_2;
    }
    else if (buf_len >= HAPROXY_PROTOCOL_V1_MIN_HDR_LEN
             && memcmp(buf, HAPROXY_PROTOCOL_V1_SIG, HAPROXY_PROTOCOL_V1_SIG_LEN) == 0)
    {
        return HAPROXY_PROTOCOL_VERSION_1;
    }
    return HAPROXY_PROTOCOL_VERSION_INVALID;
}

int
haproxy_protocol_header_len(const uint8_t *buf, const int buf_len,
                            const haproxy_protocol_version_t version)
{
    switch (version)
    {
        case HAPROXY_PROTOCOL_VERSION_1:
        {
            const char *end = memchr(buf, '\r', buf_len - 1);
            /* partial or invalid header */
            if (!end || end[1] != '\n')
            {
                return -1;
            }
            return (int)(end + 2 - (char *)buf);
        }

        case HAPROXY_PROTOCOL_VERSION_2:
            /* byte 15 and 16 contain the length */
            return HAPROXY_PROTOCOL_V2_MIN_HDR_LEN + ntohps(*(uint16_t *)(buf + 14));

        default:
            return -1;
    }
}

/*
 * Parse a port number from a string.
 *
 * @param port_str - The string to parse.
 *
 * @return - The port number or -1 if the string is invalid.
 */
uint16_t
haproxy_protocol_parse_port(const char *port_str)
{
    char *endptr;
    errno = 0;

    long port = strtol(port_str, &endptr, 10);
    if (errno != 0 || endptr == port_str || *endptr != '\0' || port <= 0 || port > 65535)
    {
        return -1;
    }
    return (uint16_t)port;
}

/*
 * Set the source and destination addresses and ports in the proxy protocol
 * info structure for later use.
 *
 * @param hpi - The haproxy protocol info structure to store the addresses.
 * @param ver - The version of the PROXY protocol.
 * @param fam - The address family (supports: AF_INET or AF_INET6).
 * @param st - The socket type.
 * @param src_addr - The source address.
 * @param dst_addr - The destination address.
 * @param src_port - The source port.
 * @param dst_port - The destination port.
 */
void
haproxy_protocol_set_addr(struct haproxy_protocol_info *hpi,
                          const haproxy_protocol_version_t ver, const int fam, const int st,
                          const void *src_addr, const void *dst_addr,
                          const uint16_t src_port, const uint16_t dst_port)
{

    hpi->version = ver;
    hpi->sock_type = st;
    if (fam == AF_INET)
    {
        hpi->src.addr.sa.sa_family = AF_INET;
        hpi->dst.addr.sa.sa_family = AF_INET;
        hpi->src.addr.in4.sin_addr.s_addr = *(uint32_t *)src_addr;
        hpi->dst.addr.in4.sin_addr.s_addr = *(uint32_t *)dst_addr;
        hpi->src.addr.in4.sin_port = src_port;
        hpi->dst.addr.in4.sin_port = dst_port;
        msg(M_DEBUG, "PROXY protocol %s: SRC %s:%u",
            ver == HAPROXY_PROTOCOL_VERSION_2 ? "v2" : "v1",
            inet_ntoa(hpi->src.addr.in4.sin_addr),
            ntohs(hpi->src.addr.in4.sin_port));
        msg(M_DEBUG, "PROXY protocol %s: DST %s:%u",
            ver == HAPROXY_PROTOCOL_VERSION_2 ? "v2" : "v1",
            inet_ntoa(hpi->dst.addr.in4.sin_addr),
            ntohs(hpi->dst.addr.in4.sin_port));
    }
    else if (fam == AF_INET6)
    {
        hpi->src.addr.sa.sa_family = AF_INET6;
        hpi->dst.addr.sa.sa_family = AF_INET6;
        memcpy(&hpi->src.addr.in6.sin6_addr, src_addr, sizeof(struct in6_addr));
        memcpy(&hpi->dst.addr.in6.sin6_addr, dst_addr, sizeof(struct in6_addr));
        hpi->src.addr.in6.sin6_port = src_port;
        hpi->dst.addr.in6.sin6_port = dst_port;

        char ip6_str[INET6_ADDRSTRLEN];
        if (inet_ntop(AF_INET6, &hpi->src.addr.in6.sin6_addr, ip6_str,
                      INET6_ADDRSTRLEN))
        {
            msg(M_DEBUG, "PROXY protocol %s: SRC %s:%u",
                ver == HAPROXY_PROTOCOL_VERSION_2 ? "v2" : "v1",
                ip6_str,
                ntohs(hpi->src.addr.in6.sin6_port));
        }
        else
        {
            msg(M_NONFATAL, "PROXY protocol %s: could not parse source address",
                ver == HAPROXY_PROTOCOL_VERSION_2 ? "v2" : "v1");
        }
        if (inet_ntop(AF_INET6, &hpi->dst.addr.in6.sin6_addr, ip6_str,
                      INET6_ADDRSTRLEN))
        {
            msg(M_DEBUG, "PROXY protocol %s: DST %s:%u",
                ver == HAPROXY_PROTOCOL_VERSION_2 ? "v2" : "v1",
                ip6_str,
                ntohs(hpi->dst.addr.in6.sin6_port));
        }
        else
        {
            msg(M_NONFATAL, "PROXY protocol %s: could not parse destination address",
                ver == HAPROXY_PROTOCOL_VERSION_2 ? "v2" : "v1");
        }
    }
    else
    {
        msg(M_NONFATAL, "PROXY protocol %s: unsupported address family",
            ver == HAPROXY_PROTOCOL_VERSION_2 ? "v2" : "v1");
    }
}

/*
 * Split the v1 header line into words (space-separated)
 *
 * @param words - The array to store the words.
 * @param line - The header line to split.
 * @param len - The length of the header line.
 *
 * @return - The number of words found or -1 if an error occurred.
 */
int
haproxy_protocol_v1_split_words(char words[][HAPROXY_PROTOCOL_V1_MAX_WORD_LEN],
                                const char *line, int len)
{
    int word_num = 0;
    const char *start = line;
    for (int i = 0; i < len; ++i)
    {
        if (line[i] == ' ')
        {
            if (word_num < HAPROXY_PROTOCOL_V1_MAX_WORDS)
            {
                int word_len = (int)(line + i - start);
                if (word_len < HAPROXY_PROTOCOL_V1_MAX_WORD_LEN)
                {
                    memcpy(words[word_num], start, word_len);
                    words[word_num][word_len] = '\0';
                    ++word_num;
                }
                else
                {
                    msg(M_NONFATAL, "PROXY protocol v1: word too long");
                    return -1;
                }
            }
            start = line + i + 1;
        }
    }
    return word_num;
}

/*
 * Parse the PROXY protocol v1 header line.
 *
 * @param hpi - The haproxy protocol info structure to store the parsed data.
 * @param line - The header line to parse.
 * @param len - The length of the header line.
 *
 * @return - true if the header was successfully parsed.
 */
bool
haproxy_protocol_parse_v1(struct haproxy_protocol_info *hpi,
                          const char *line, int len)
{
    const haproxy_protocol_version_t version = HAPROXY_PROTOCOL_VERSION_1;
    char words[HAPROXY_PROTOCOL_V1_MAX_WORDS][HAPROXY_PROTOCOL_V1_MAX_WORD_LEN];

    char *end = memchr(line, '\r', len - 1);
    if (!end || end[1] != '\n') /* partial or invalid header */
    {
        return false;
    }
    *end = ' '; /* replace CRLF with space for easier splitting */
    int size = (int)(end - line + 1);

    int word_num = haproxy_protocol_v1_split_words(words, line, size);
    if (word_num < 3)
    {
        msg(M_NONFATAL, "PROXY protocol v1: invalid header");
        return false;
    }

    if (strcmp(words[1], "TCP4") == 0)
    {
        msg(M_DEBUG, "PROXY protocol v1: TCP4 protocol");
        struct in_addr ip4_src_addr, ip4_dst_addr;
        if (inet_pton(AF_INET, words[2], &ip4_src_addr) != 1)
        {
            msg(M_NONFATAL,
                "PROXY protocol v1: could not parse source address");
            return false;
        }
        if (inet_pton(AF_INET, words[3], &ip4_dst_addr) != 1)
        {
            msg(M_NONFATAL,
                "PROXY protocol v1: could not parse destination address");
            return false;
        }
        haproxy_protocol_set_addr(hpi, version, AF_INET, SOCK_STREAM,
                                  &ip4_src_addr, &ip4_dst_addr,
                                  ntohs(haproxy_protocol_parse_port(words[4])),
                                  ntohs(haproxy_protocol_parse_port(words[5])));
        return true;
    }
    else if (strcmp(words[1], "TCP6") == 0)
    {
        msg(M_DEBUG, "PROXY protocol v1: TCP6 protocol");
        struct in6_addr ip6_src_addr, ip6_dst_addr;
        if (inet_pton(AF_INET6, words[2], &ip6_src_addr) != 1)
        {
            msg(M_NONFATAL,
                "PROXY protocol v1: could not parse source address");
            return false;
        }
        if (inet_pton(AF_INET6, words[3], &ip6_dst_addr) != 1)
        {
            msg(M_NONFATAL,
                "PROXY protocol v1: could not parse destination address");
            return false;
        }
        haproxy_protocol_set_addr(hpi, version, AF_INET6, SOCK_STREAM,
                                  &ip6_src_addr, &ip6_dst_addr,
                                  ntohs(haproxy_protocol_parse_port(words[4])),
                                  ntohs(haproxy_protocol_parse_port(words[5])));
        return true;
    }
    else
    {
        msg(M_NONFATAL, "PROXY protocol v1: unsupported protocol");
        return false;
    }
}

/*
 * Parse the PROXY protocol v2 header
 *
 * @param hpi - The haproxy protocol info structure to store the parsed data.
 *
 * @return - The number of bytes parsed.
 */
int
haproxy_protocol_parse_v2(struct haproxy_protocol_info *hpi)
{
    size_t addr_len = 0;
    int pos = HAPROXY_PROTOCOL_V2_SIG_LEN + sizeof(header->v2.ver_cmd);
    const haproxy_protocol_version_t version = HAPROXY_PROTOCOL_VERSION_2;

    switch (header->v2.ver_cmd & HAPROXY_PROTOCOL_V2_CMD_MASK)
    {
        case HAPROXY_PROTOCOL_V2_LOCAL_CMD:
            /*
             * this command is sent by the proxy for health-checks and similar
             * and it doesn't make much sense in the openvpn context, so we
             * ignore the whole header
             */
            msg(M_DEBUG, "PROXY protocol v2: LOCAL command");
            parsing_state = HAPROXY_PROTOCOL_PARSING_STATE_IGNORE;
            break;

        case HAPROXY_PROTOCOL_V2_PROXY_CMD:
            msg(M_DEBUG, "PROXY protocol v2: PROXY command");
            break;

        default:
            msg(M_DEBUG, "PROXY protocol v2: unknown command");
            parsing_state = HAPROXY_PROTOCOL_PARSING_STATE_INVALID;
    }

    if (parsing_state != HAPROXY_PROTOCOL_PARSING_STATE_OK)
    {
        return pos;
    }
    pos += sizeof(header->v2.fam);

    switch (header->v2.fam)
    {
        case HAPROXY_PROTOCOL_V2_AF_INET | HAPROXY_PROTOCOL_V2_TP_STREAM:
            msg(M_DEBUG, "PROXY protocol v2: TCP over IPv4.");
            haproxy_protocol_set_addr(hpi, version, AF_INET, SOCK_STREAM,
                                      &header->v2.addr.ip4.src_addr,
                                      &header->v2.addr.ip4.dst_addr,
                                      header->v2.addr.ip4.src_port,
                                      header->v2.addr.ip4.dst_port);
            addr_len = HAPROXY_PROTOCOL_V2_ADDR_LEN_IPV4;
            break;

        case HAPROXY_PROTOCOL_V2_AF_INET | HAPROXY_PROTOCOL_V2_TP_DGRAM:
            msg(M_DEBUG, "PROXY protocol v2: UDP over IPv4");
            haproxy_protocol_set_addr(hpi, version, AF_INET, SOCK_DGRAM,
                                      &header->v2.addr.ip4.src_addr,
                                      &header->v2.addr.ip4.dst_addr,
                                      header->v2.addr.ip4.src_port,
                                      header->v2.addr.ip4.dst_port);
            addr_len = HAPROXY_PROTOCOL_V2_ADDR_LEN_IPV4;
            break;

        case HAPROXY_PROTOCOL_V2_AF_INET6 | HAPROXY_PROTOCOL_V2_TP_STREAM:
            msg(M_DEBUG, "PROXY protocol v2: TCP over IPv6");
            haproxy_protocol_set_addr(hpi, version, AF_INET6, SOCK_STREAM,
                                      header->v2.addr.ip6.src_addr,
                                      header->v2.addr.ip6.dst_addr,
                                      header->v2.addr.ip6.src_port,
                                      header->v2.addr.ip6.dst_port);
            addr_len = HAPROXY_PROTOCOL_V2_ADDR_LEN_IPV6;
            break;

        case HAPROXY_PROTOCOL_V2_AF_INET6 | HAPROXY_PROTOCOL_V2_TP_DGRAM:
            msg(M_DEBUG, "PROXY protocol v2: UDP over IPv6");
            haproxy_protocol_set_addr(hpi, version, AF_INET6, SOCK_DGRAM,
                                      header->v2.addr.ip6.src_addr,
                                      header->v2.addr.ip6.dst_addr,
                                      header->v2.addr.ip6.src_port,
                                      header->v2.addr.ip6.dst_port);
            addr_len = HAPROXY_PROTOCOL_V2_ADDR_LEN_IPV6;
            break;

        case HAPROXY_PROTOCOL_V2_AF_UNIX | HAPROXY_PROTOCOL_V2_TP_STREAM:
            msg(M_DEBUG, "PROXY protocol v2: AF_UNIX stream");
            haproxy_protocol_set_addr(hpi, version, AF_UNIX, SOCK_STREAM,
                                      header->v2.addr.unx.src_addr,
                                      header->v2.addr.unx.dst_addr, 0, 0);
            addr_len = HAPROXY_PROTOCOL_V2_ADDR_LEN_UNIX;
            break;

        case HAPROXY_PROTOCOL_V2_AF_UNIX | HAPROXY_PROTOCOL_V2_TP_DGRAM:
            msg(M_DEBUG, "PROXY protocol v2: AF_UNIX datagram");
            haproxy_protocol_set_addr(hpi, version, AF_UNIX, SOCK_DGRAM,
                                      header->v2.addr.unx.src_addr,
                                      header->v2.addr.unx.dst_addr, 0, 0);
            addr_len = HAPROXY_PROTOCOL_V2_ADDR_LEN_UNIX;
            break;

        default:
            if ((header->v2.fam & HAPROXY_PROTOCOL_V2_AF_MASK) == HAPROXY_PROTOCOL_V2_AF_UNSPEC
                || (header->v2.fam & HAPROXY_PROTOCOL_V2_TP_MASK) == HAPROXY_PROTOCOL_V2_TP_UNSPEC)
            {
                msg(M_DEBUG, "PROXY protocol v2: UNSPEC address family or transport protocol");
                parsing_state = HAPROXY_PROTOCOL_PARSING_STATE_IGNORE;
                break;
            }
            msg(M_DEBUG, "PROXY protocol v2: unknown address family (0x%02x) "
                "or transport protocol (0x%02x)",
                header->v2.fam & HAPROXY_PROTOCOL_V2_AF_MASK,
                header->v2.fam & HAPROXY_PROTOCOL_V2_TP_MASK);
            parsing_state = HAPROXY_PROTOCOL_PARSING_STATE_IGNORE;
            break;
    }
    return (int)(pos + sizeof(header->v2.len) + addr_len);
}

bool
haproxy_protocol_parse(struct haproxy_protocol_info *hpi, const uint8_t *buf, const int buf_len)
{
    const haproxy_protocol_version_t version = haproxy_protocol_version(buf, buf_len);
    header_len = buf_len;
    header = (haproxy_protocol_header_t *)buf;

    if (!hpi)
    {
        msg(M_NONFATAL, "PROXY protocol: invalid haproxy protocol info structure");
        return false;
    }

    switch (version)
    {
        case HAPROXY_PROTOCOL_VERSION_2:
        {
            if ((header->v2.ver_cmd & HAPROXY_PROTOCOL_V2_VER_MASK) == HAPROXY_PROTOCOL_V2_VER)
            {
                haproxy_protocol_parse_v2(hpi);
                if (parsing_state != HAPROXY_PROTOCOL_PARSING_STATE_OK)
                {
                    msg(M_DEBUG, "PROXY protocol v2: %s header",
                        parsing_state == HAPROXY_PROTOCOL_PARSING_STATE_IGNORE ? "ignoring" : "invalid");
                    return false;
                }
                return true;
            }
            else
            {
                msg(M_NONFATAL, "PROXY protocol v2: expected version 2, got %d",
                    (header->v2.ver_cmd & HAPROXY_PROTOCOL_V2_VER_MASK) >> 4);
                return false;
            }
        }

        case HAPROXY_PROTOCOL_VERSION_1:
            msg(M_DEBUG, "PROXY protocol header v1: %.*s", header_len - 2, header->v1.line);
            return haproxy_protocol_parse_v1(hpi, header->v1.line, header_len);

        default:
            return false;
    }
}

void
haproxy_protocol_reset(struct haproxy_protocol_info *hpi)
{
    header = NULL;
    header_len = 0;
    parsing_state = HAPROXY_PROTOCOL_PARSING_STATE_OK;
}
