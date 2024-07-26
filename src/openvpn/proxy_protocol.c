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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "error.h"
#include "proxy_protocol.h"

#define PROXY_PROTOCOL_V1_MAX_WORDS 6
#define PROXY_PROTOCOL_V1_MAX_WORD_LEN 40

typedef enum
{
    PROXY_PROTOCOL_PARSING_STATE_INVALID = -1,
    PROXY_PROTOCOL_PARSING_STATE_OK = 0,
    PROXY_PROTOCOL_PARSING_STATE_IGNORE = 1,
} proxy_protocol_parsing_state_t;

static const size_t PROXY_PROTOCOL_V2_ADDR_LEN_IPV4 = 12;
static const size_t PROXY_PROTOCOL_V2_ADDR_LEN_IPV6 = 36;
static const size_t PROXY_PROTOCOL_V2_ADDR_LEN_UNIX = 216;

static proxy_protocol_header_t header;
static uint16_t header_len;
static proxy_protocol_parsing_state_t parsing_state = PROXY_PROTOCOL_PARSING_STATE_OK;

proxy_protocol_version_t
proxy_protocol_version(const uint8_t *buf, const int buf_len)
{
    if (buf_len >= PROXY_PROTOCOL_V2_MIN_HDR_LEN
        && memcmp(buf, PROXY_PROTOCOL_V2_SIG, PROXY_PROTOCOL_V2_SIG_LEN) == 0)
    {
        return PROXY_PROTOCOL_VERSION_2;
    }
    else if (buf_len >= PROXY_PROTOCOL_V1_MIN_HDR_LEN
             && memcmp(buf, PROXY_PROTOCOL_V1_SIG, PROXY_PROTOCOL_V1_SIG_LEN) == 0)
    {
        return PROXY_PROTOCOL_VERSION_1;
    }
    return PROXY_PROTOCOL_VERSION_INVALID;
}

int
proxy_protocol_header_len(const uint8_t *buf, const int buf_len,
                          const proxy_protocol_version_t version)
{
    memcpy(&header, buf, buf_len);

    switch (version)
    {
        case PROXY_PROTOCOL_VERSION_1:
        {
            char *end = memchr(header.v1.line, '\r', buf_len - 1);
            if (!end || end[1] != '\n')
            {
                return -1; /* partial or invalid header */
            }
            return (int)(end + 2 - header.v1.line);
        }

        case PROXY_PROTOCOL_VERSION_2:
            return PROXY_PROTOCOL_V2_MIN_HDR_LEN + ntohps(header.v2.len);

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
proxy_protocol_parse_port(const char *port_str)
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
 * @param ppi - The proxy protocol info structure to store the addresses.
 * @param ver - The version of the PROXY protocol.
 * @param fam - The address family (supports: AF_INET or AF_INET6).
 * @param st - The socket type.
 * @param src_addr - The source address.
 * @param dst_addr - The destination address.
 * @param src_port - The source port.
 * @param dst_port - The destination port.
 */
void
proxy_protocol_set_addr(struct proxy_protocol_info *ppi,
                        const proxy_protocol_version_t ver, const int fam, const int st,
                        const void *src_addr, const void *dst_addr,
                        const uint16_t src_port, const uint16_t dst_port)
{

    ppi->version = ver;
    ppi->sock_type = st;
    if (fam == AF_INET)
    {
        ppi->src.addr.sa.sa_family = AF_INET;
        ppi->dst.addr.sa.sa_family = AF_INET;
        memcpy(&ppi->src.addr.in4.sin_addr, (uint32_t *)src_addr,
               sizeof(struct in_addr));
        memcpy(&ppi->dst.addr.in4.sin_addr, (uint32_t *)dst_addr,
               sizeof(struct in_addr));
        ppi->src.addr.in4.sin_port = src_port;
        ppi->dst.addr.in4.sin_port = dst_port;
        msg(M_DEBUG, "PROXY protocol: SRC: %s:%u",
            inet_ntoa(ppi->src.addr.in4.sin_addr),
            ntohs(ppi->src.addr.in4.sin_port));
        msg(M_DEBUG, "PROXY protocol: DST: %s:%u",
            inet_ntoa(ppi->dst.addr.in4.sin_addr),
            ntohs(ppi->dst.addr.in4.sin_port));
    }
    else if (fam == AF_INET6)
    {
        ppi->src.addr.sa.sa_family = AF_INET6;
        ppi->dst.addr.sa.sa_family = AF_INET6;
        memcpy(&ppi->src.addr.in6.sin6_addr, src_addr, sizeof(struct in6_addr));
        memcpy(&ppi->dst.addr.in6.sin6_addr, dst_addr, sizeof(struct in6_addr));
        ppi->src.addr.in6.sin6_port = src_port;
        ppi->dst.addr.in6.sin6_port = dst_port;

        char ip6_str[INET6_ADDRSTRLEN];
        if (inet_ntop(AF_INET6, &ppi->src.addr.in6.sin6_addr, ip6_str,
                      INET6_ADDRSTRLEN))
        {
            msg(M_DEBUG, "PROXY protocol: SRC: %s:%u", ip6_str,
                ntohs(ppi->src.addr.in6.sin6_port));
        }
        else
        {
            msg(M_NONFATAL, "PROXY protocol: could not parse source address");
        }
        if (inet_ntop(AF_INET6, &ppi->dst.addr.in6.sin6_addr, ip6_str,
                      INET6_ADDRSTRLEN))
        {
            msg(M_DEBUG, "PROXY protocol: DST: %s:%u", ip6_str,
                ntohs(ppi->dst.addr.in6.sin6_port));
        }
        else
        {
            msg(M_NONFATAL,
                "PROXY protocol: could not parse destination address");
        }
    }
    else
    {
        msg(M_NONFATAL, "PROXY protocol: unsupported address family");
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
proxy_protocol_v1_split_words(char words[][PROXY_PROTOCOL_V1_MAX_WORD_LEN],
                              const char *line,
                              int len)
{
    int word_num = 0;
    const char *start = line;
    for (int i = 0; i < len; ++i)
    {
        if (line[i] == ' ')
        {
            if (word_num < PROXY_PROTOCOL_V1_MAX_WORDS)
            {
                int word_len = (int)(line + i - start);
                if (word_len < PROXY_PROTOCOL_V1_MAX_WORD_LEN)
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
 * @param ppi - The proxy protocol info structure to store the parsed data.
 * @param line - The header line to parse.
 * @param len - The length of the header line.
 *
 * @return - true if the header was successfully parsed.
 */
bool
proxy_protocol_parse_v1(struct proxy_protocol_info *ppi,
                        const char *line,
                        int len)
{
    const proxy_protocol_version_t version = PROXY_PROTOCOL_VERSION_1;
    char words[PROXY_PROTOCOL_V1_MAX_WORDS][PROXY_PROTOCOL_V1_MAX_WORD_LEN];

    char *end = memchr(line, '\r', len - 1);
    if (!end || end[1] != '\n') /* partial or invalid header */
    {
        return false;
    }
    *end = ' '; /* replace CRLF with space for easier splitting */
    int size = (int)(end - line + 1);

    int word_num = proxy_protocol_v1_split_words(words, line, size);
    if (word_num < 3)
    {
        msg(M_NONFATAL, "PROXY protocol v1: could not split header");
        return false;
    }

    if (strcmp(words[1], "UNKNOWN") == 0)
    {
        msg(M_DEBUG, "PROXY protocol v1: UNKNOWN protocol, ignoring header");
        return true;
    }
    else if (strcmp(words[1], "TCP4") == 0)
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
        proxy_protocol_set_addr(ppi, version, AF_INET, SOCK_STREAM,
                                &ip4_src_addr, &ip4_dst_addr,
                                ntohs(proxy_protocol_parse_port(words[4])),
                                ntohs(proxy_protocol_parse_port(words[5])));
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
        proxy_protocol_set_addr(ppi, version, AF_INET6, SOCK_STREAM,
                                &ip6_src_addr, &ip6_dst_addr,
                                ntohs(proxy_protocol_parse_port(words[4])),
                                ntohs(proxy_protocol_parse_port(words[5])));
        return true;
    }
    else
    {
        msg(M_NONFATAL, "PROXY protocol v1: unsupported protocol");
        return false;
    }
}

/*
 * Parse the PROXY protocol v2 header.
 *
 * @param ppi - The proxy protocol info structure to store the parsed data.
 * @param header - The header to parse.
 *
 * @return - The number of bytes parsed or 0 if the header can be ignored.
 */
int
proxy_protocol_parse_v2(struct proxy_protocol_info *ppi)
{
    size_t addr_len = 0;
    int pos = PROXY_PROTOCOL_V2_SIG_LEN + sizeof(header.v2.ver_cmd);
    const proxy_protocol_version_t version = PROXY_PROTOCOL_VERSION_2;

    switch (header.v2.ver_cmd & PROXY_PROTOCOL_V2_CMD_MASK)
    {
        case PROXY_PROTOCOL_V2_LOCAL_CMD:
            /* the receiver must accept this connection as valid and must use
             * the real connection endpoints and discard the protocol block
             * including the family which is ignored */
            msg(M_DEBUG, "PROXY protocol v2: LOCAL command");
            parsing_state = PROXY_PROTOCOL_PARSING_STATE_IGNORE;
            break;

        case PROXY_PROTOCOL_V2_PROXY_CMD:
            msg(M_DEBUG, "PROXY protocol v2: PROXY command");
            break;

        default:
            msg(M_DEBUG, "PROXY protocol v2: UNSPEC or unknown command");
            parsing_state = PROXY_PROTOCOL_PARSING_STATE_INVALID;
    }

    if (parsing_state != PROXY_PROTOCOL_PARSING_STATE_OK)
    {
        return pos;
    }
    pos += sizeof(header.v2.fam);

    switch (header.v2.fam)
    {
        case PROXY_PROTOCOL_V2_AF_INET | PROXY_PROTOCOL_V2_TP_STREAM:
            msg(M_DEBUG, "PROXY protocol v2: TCP over IPv4.");
            proxy_protocol_set_addr(ppi, version, AF_INET, SOCK_STREAM,
                                    &header.v2.addr.ip4.src_addr,
                                    &header.v2.addr.ip4.dst_addr,
                                    header.v2.addr.ip4.src_port,
                                    header.v2.addr.ip4.dst_port);
            addr_len = PROXY_PROTOCOL_V2_ADDR_LEN_IPV4;
            break;

        case PROXY_PROTOCOL_V2_AF_INET | PROXY_PROTOCOL_V2_TP_DGRAM:
            msg(M_DEBUG, "PROXY protocol v2: UDP over IPv4");
            proxy_protocol_set_addr(ppi, version, AF_INET, SOCK_DGRAM,
                                    &header.v2.addr.ip4.src_addr,
                                    &header.v2.addr.ip4.dst_addr,
                                    header.v2.addr.ip4.src_port,
                                    header.v2.addr.ip4.dst_port);
            addr_len = PROXY_PROTOCOL_V2_ADDR_LEN_IPV4;
            break;

        case PROXY_PROTOCOL_V2_AF_INET6 | PROXY_PROTOCOL_V2_TP_STREAM:
            msg(M_DEBUG, "PROXY protocol v2: TCP over IPv6");
            proxy_protocol_set_addr(ppi, version, AF_INET6, SOCK_STREAM,
                                    header.v2.addr.ip6.src_addr,
                                    header.v2.addr.ip6.dst_addr,
                                    header.v2.addr.ip6.src_port,
                                    header.v2.addr.ip6.dst_port);
            addr_len = PROXY_PROTOCOL_V2_ADDR_LEN_IPV6;
            break;

        case PROXY_PROTOCOL_V2_AF_INET6 | PROXY_PROTOCOL_V2_TP_DGRAM:
            msg(M_DEBUG, "PROXY protocol v2: UDP over IPv6");
            proxy_protocol_set_addr(ppi, version, AF_INET6, SOCK_DGRAM,
                                    header.v2.addr.ip6.src_addr,
                                    header.v2.addr.ip6.dst_addr,
                                    header.v2.addr.ip6.src_port,
                                    header.v2.addr.ip6.dst_port);
            addr_len = PROXY_PROTOCOL_V2_ADDR_LEN_IPV6;
            break;

        case PROXY_PROTOCOL_V2_AF_UNIX | PROXY_PROTOCOL_V2_TP_STREAM:
            msg(M_DEBUG, "PROXY protocol v2: AF_UNIX stream");
            proxy_protocol_set_addr(ppi, version, AF_UNIX, SOCK_STREAM,
                                    header.v2.addr.unx.src_addr,
                                    header.v2.addr.unx.dst_addr, 0, 0);
            addr_len = PROXY_PROTOCOL_V2_ADDR_LEN_UNIX;
            break;

        case PROXY_PROTOCOL_V2_AF_UNIX | PROXY_PROTOCOL_V2_TP_DGRAM:
            msg(M_DEBUG, "PROXY protocol v2: AF_UNIX datagram");
            proxy_protocol_set_addr(ppi, version, AF_UNIX, SOCK_DGRAM,
                                    header.v2.addr.unx.src_addr,
                                    header.v2.addr.unx.dst_addr, 0, 0);
            addr_len = PROXY_PROTOCOL_V2_ADDR_LEN_UNIX;
            break;

        default:
            msg(M_DEBUG, "PROXY protocol v2: UNSPEC or unknown address family");
            parsing_state = PROXY_PROTOCOL_PARSING_STATE_INVALID;
            break;
    }
    return (int)(pos + sizeof(header.v2.len) + addr_len);
}

bool
proxy_protocol_parse(struct proxy_protocol_info *ppi, const struct buffer *buf)
{
    const proxy_protocol_version_t version = proxy_protocol_version(BPTR(buf), BLEN(buf));

    header_len = BLEN(buf);
    memcpy(&header, BPTR(buf), header_len);

    switch (version)
    {
        case PROXY_PROTOCOL_VERSION_2:
        {
            if ((header.v2.ver_cmd & PROXY_PROTOCOL_V2_VER_MASK) == PROXY_PROTOCOL_V2_VER)
            {
                proxy_protocol_parse_v2(ppi);
                if (parsing_state == PROXY_PROTOCOL_PARSING_STATE_IGNORE)
                {
                    msg(M_DEBUG, "PROXY protocol v2: ignoring header");
                    return true;
                }
                else if (parsing_state == PROXY_PROTOCOL_PARSING_STATE_INVALID)
                {
                    return false;
                }
                msg(M_DEBUG, "PROXY protocol v2: header parsed");
                return true;
            }
            else
            {
                msg(M_NONFATAL, "PROXY protocol v2: expected version 2, got %d",
                    header.v2.ver_cmd & PROXY_PROTOCOL_V2_VER_MASK);
                return false;
            }
        }

        case PROXY_PROTOCOL_VERSION_1:
            msg(M_DEBUG, "PROXY protocol header v1: %.*s", BLEN(buf) - 2, header.v1.line);
            return proxy_protocol_parse_v1(ppi, header.v1.line, BLEN(buf));

        default:
            return false;
    }
}

void
proxy_protocol_free(struct proxy_protocol_info *ppi)
{
    gc_free(&ppi->gc);
}
