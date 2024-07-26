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

static const uint32_t CRC32C_TABLE[256] =
{
    0x00000000L, 0xF26B8303L, 0xE13B70F7L, 0x1350F3F4L,
    0xC79A971FL, 0x35F1141CL, 0x26A1E7E8L, 0xD4CA64EBL,
    0x8AD958CFL, 0x78B2DBCCL, 0x6BE22838L, 0x9989AB3BL,
    0x4D43CFD0L, 0xBF284CD3L, 0xAC78BF27L, 0x5E133C24L,
    0x105EC76FL, 0xE235446CL, 0xF165B798L, 0x030E349BL,
    0xD7C45070L, 0x25AFD373L, 0x36FF2087L, 0xC494A384L,
    0x9A879FA0L, 0x68EC1CA3L, 0x7BBCEF57L, 0x89D76C54L,
    0x5D1D08BFL, 0xAF768BBCL, 0xBC267848L, 0x4E4DFB4BL,
    0x20BD8EDEL, 0xD2D60DDDL, 0xC186FE29L, 0x33ED7D2AL,
    0xE72719C1L, 0x154C9AC2L, 0x061C6936L, 0xF477EA35L,
    0xAA64D611L, 0x580F5512L, 0x4B5FA6E6L, 0xB93425E5L,
    0x6DFE410EL, 0x9F95C20DL, 0x8CC531F9L, 0x7EAEB2FAL,
    0x30E349B1L, 0xC288CAB2L, 0xD1D83946L, 0x23B3BA45L,
    0xF779DEAEL, 0x05125DADL, 0x1642AE59L, 0xE4292D5AL,
    0xBA3A117EL, 0x4851927DL, 0x5B016189L, 0xA96AE28AL,
    0x7DA08661L, 0x8FCB0562L, 0x9C9BF696L, 0x6EF07595L,
    0x417B1DBCL, 0xB3109EBFL, 0xA0406D4BL, 0x522BEE48L,
    0x86E18AA3L, 0x748A09A0L, 0x67DAFA54L, 0x95B17957L,
    0xCBA24573L, 0x39C9C670L, 0x2A993584L, 0xD8F2B687L,
    0x0C38D26CL, 0xFE53516FL, 0xED03A29BL, 0x1F682198L,
    0x5125DAD3L, 0xA34E59D0L, 0xB01EAA24L, 0x42752927L,
    0x96BF4DCCL, 0x64D4CECFL, 0x77843D3BL, 0x85EFBE38L,
    0xDBFC821CL, 0x2997011FL, 0x3AC7F2EBL, 0xC8AC71E8L,
    0x1C661503L, 0xEE0D9600L, 0xFD5D65F4L, 0x0F36E6F7L,
    0x61C69362L, 0x93AD1061L, 0x80FDE395L, 0x72966096L,
    0xA65C047DL, 0x5437877EL, 0x4767748AL, 0xB50CF789L,
    0xEB1FCBADL, 0x197448AEL, 0x0A24BB5AL, 0xF84F3859L,
    0x2C855CB2L, 0xDEEEDFB1L, 0xCDBE2C45L, 0x3FD5AF46L,
    0x7198540DL, 0x83F3D70EL, 0x90A324FAL, 0x62C8A7F9L,
    0xB602C312L, 0x44694011L, 0x5739B3E5L, 0xA55230E6L,
    0xFB410CC2L, 0x092A8FC1L, 0x1A7A7C35L, 0xE811FF36L,
    0x3CDB9BDDL, 0xCEB018DEL, 0xDDE0EB2AL, 0x2F8B6829L,
    0x82F63B78L, 0x709DB87BL, 0x63CD4B8FL, 0x91A6C88CL,
    0x456CAC67L, 0xB7072F64L, 0xA457DC90L, 0x563C5F93L,
    0x082F63B7L, 0xFA44E0B4L, 0xE9141340L, 0x1B7F9043L,
    0xCFB5F4A8L, 0x3DDE77ABL, 0x2E8E845FL, 0xDCE5075CL,
    0x92A8FC17L, 0x60C37F14L, 0x73938CE0L, 0x81F80FE3L,
    0x55326B08L, 0xA759E80BL, 0xB4091BFFL, 0x466298FCL,
    0x1871A4D8L, 0xEA1A27DBL, 0xF94AD42FL, 0x0B21572CL,
    0xDFEB33C7L, 0x2D80B0C4L, 0x3ED04330L, 0xCCBBC033L,
    0xA24BB5A6L, 0x502036A5L, 0x4370C551L, 0xB11B4652L,
    0x65D122B9L, 0x97BAA1BAL, 0x84EA524EL, 0x7681D14DL,
    0x2892ED69L, 0xDAF96E6AL, 0xC9A99D9EL, 0x3BC21E9DL,
    0xEF087A76L, 0x1D63F975L, 0x0E330A81L, 0xFC588982L,
    0xB21572C9L, 0x407EF1CAL, 0x532E023EL, 0xA145813DL,
    0x758FE5D6L, 0x87E466D5L, 0x94B49521L, 0x66DF1622L,
    0x38CC2A06L, 0xCAA7A905L, 0xD9F75AF1L, 0x2B9CD9F2L,
    0xFF56BD19L, 0x0D3D3E1AL, 0x1E6DCDEEL, 0xEC064EEDL,
    0xC38D26C4L, 0x31E6A5C7L, 0x22B65633L, 0xD0DDD530L,
    0x0417B1DBL, 0xF67C32D8L, 0xE52CC12CL, 0x1747422FL,
    0x49547E0BL, 0xBB3FFD08L, 0xA86F0EFCL, 0x5A048DFFL,
    0x8ECEE914L, 0x7CA56A17L, 0x6FF599E3L, 0x9D9E1AE0L,
    0xD3D3E1ABL, 0x21B862A8L, 0x32E8915CL, 0xC083125FL,
    0x144976B4L, 0xE622F5B7L, 0xF5720643L, 0x07198540L,
    0x590AB964L, 0xAB613A67L, 0xB831C993L, 0x4A5A4A90L,
    0x9E902E7BL, 0x6CFBAD78L, 0x7FAB5E8CL, 0x8DC0DD8FL,
    0xE330A81AL, 0x115B2B19L, 0x020BD8EDL, 0xF0605BEEL,
    0x24AA3F05L, 0xD6C1BC06L, 0xC5914FF2L, 0x37FACCF1L,
    0x69E9F0D5L, 0x9B8273D6L, 0x88D28022L, 0x7AB90321L,
    0xAE7367CAL, 0x5C18E4C9L, 0x4F48173DL, 0xBD23943EL,
    0xF36E6F75L, 0x0105EC76L, 0x12551F82L, 0xE03E9C81L,
    0x34F4F86AL, 0xC69F7B69L, 0xD5CF889DL, 0x27A40B9EL,
    0x79B737BAL, 0x8BDCB4B9L, 0x988C474DL, 0x6AE7C44EL,
    0xBE2DA0A5L, 0x4C4623A6L, 0x5F16D052L, 0xAD7D5351L
};

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

uint32_t
proxy_protocol_crc32c(const uint8_t *data, int len)
{
    uint32_t crc = 0xFFFFFFFF;
    while (len-- > 0)
    {
        crc = (crc >> 8) ^ CRC32C_TABLE[(crc ^ (*data++)) & 0xFF];
    }
    return (crc ^ 0xFFFFFFFF);
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
 * Parse a string based TLV and store the value in 'out'.
 *
 * @param ppi - The proxy protocol info structure used for memory allocation.
 * @param out - The output variable to store the parsed value.
 * @param type_str - A string representation of the TLV type (for logging).
 * @param len - The length of the TLV value.
 * @param value - The TLV value.
 */
void
proxy_protocol_parse_string_tlv(struct proxy_protocol_info *ppi, char **out, char *type_str, const uint16_t len, const uint8_t *value)
{
    if (len == 0)
    {
        msg(M_NONFATAL, "PROXY protocol v2: %s TLV empty", type_str);
        return;
    }

    *out = (char *)gc_malloc(8, false, &ppi->gc);
    memcpy(*out, value, len);
    (*out)[len] = '\0';

    if (type_str)
    {
        msg(M_DEBUG, "PROXY protocol v2: %s TLV: %s", type_str, *out);
    }
}

/*
 * Parse the CRC32C TLV and check if it matches the calculated CRC32C.
 * If there's a mismatch the parsing state is set to invalid so that the header
 * is dropped.
 *
 * @param len - The length of the TLV value.
 * @param value - The TLV value.
 *
 * @return - true if the CRC32C value matches the calculated CRC32C.
 */
bool
proxy_protocol_parse_crc32c_tlv(const uint16_t len, const uint8_t *value)
{
    if (len != 4)
    {
        msg(M_NONFATAL, "PROXY protocol v2: CRC32C TLV invalid length");
        parsing_state = PROXY_PROTOCOL_PARSING_STATE_INVALID;
        return false;
    }

    uint32_t expected_crc32c = ntohl(*(uint32_t *)value);

    /* fill with 0s the crc32 field to calculate the actual crc32 */
    *(uint32_t *)value = 0;
    uint32_t calculated_crc32c = proxy_protocol_crc32c((const uint8_t *)&header, header_len);

    if (expected_crc32c != calculated_crc32c)
    {
        msg(M_NONFATAL, "PROXY protocol v2: CRC32C mismatch, expected: 0x%08x calculated: 0x%08x. Dropping header", expected_crc32c, calculated_crc32c);
        parsing_state = PROXY_PROTOCOL_PARSING_STATE_INVALID;
        return false;
    }
    msg(M_DEBUG, "PROXY protocol v2: CRC32C match");
    return true;
}

/*
 * Parse the UNIQUE_ID TLV and store the value in ppi->unique_id
 * (and ppi->unique_id_len).
 *
 * @param ppi - The proxy protocol info structure to store the parsed data.
 * @param len - The length of the TLV value.
 * @param value - The TLV value.
 */
void
proxy_protocol_parse_uid_tlv(struct proxy_protocol_info *ppi, const uint16_t len, const uint8_t *value)
{
    if (len == 0)
    {
        msg(M_NONFATAL, "PROXY protocol v2: UNIQUE_ID TLV empty");
        return;
    }
    else if (len > PROXY_PROTOCOL_V2_TLV_UNIQUE_ID_MAX_LEN)
    {
        msg(M_NONFATAL, "PROXY protocol v2: UNIQUE_ID TLV too long");
        return;
    }

    ppi->unique_id_len = len;
    memcpy(ppi->unique_id, value, len);
    msg(M_DEBUG, "PROXY protocol v2: UNIQUE_ID: %.*s", (int)ppi->unique_id_len, ppi->unique_id);
}

/*
 * Parse the SSL TLV and store the value in ppi->ssl_client and ppi->ssl_verify.
 *
 * @param ppi - The proxy protocol info structure to store the parsed data.
 * @param len - The length of the TLV value.
 * @param value - The TLV value.
 */
void
proxy_protocol_parse_ssl_tlv(struct proxy_protocol_info *ppi, const uint16_t len, const uint8_t *value)
{
    const struct proxy_protocol_tlv_ssl *ssl = (const struct proxy_protocol_tlv_ssl *)(value);

    if (!ssl->client)
    {
        msg(M_NONFATAL, "PROXY protocol v2: SSL TLV invalid");
        return;
    }

    if (ssl->client & PROXY_PROTOCOL_V2_CLIENT_SSL)
    {
        msg(M_DEBUG, "PROXY protocol v2: client connected over SSL/TLS");
    }
    if (ssl->client & PROXY_PROTOCOL_V2_CLIENT_CERT_CONN)
    {
        msg(M_DEBUG, "PROXY protocol v2: client provided a certificate over the current connection");
    }
    if (ssl->client & PROXY_PROTOCOL_V2_CLIENT_CERT_SESS)
    {
        msg(M_DEBUG, "PROXY protocol v2: client provided a certificate at least once over the TLS session this connection belongs to");
    }

    msg(M_DEBUG, "PROXY protocol v2: client certificate verification stat: %s", ssl->verify ? "failure" : "success");
    ppi->ssl_client = ssl->client;
    ppi->ssl_verify = ssl->verify == 0;
}

/*
 * Parse a TLV and store the value in the proxy protocol info structure.
 *
 * @param ppi - The proxy protocol info structure to store the parsed data.
 * @param type - The TLV type.
 * @param len - The length of the TLV value.
 * @param value - The TLV value.
 */
void
proxy_protocol_parse_tlv(struct proxy_protocol_info *ppi, const uint8_t type, const uint16_t len, const uint8_t *value)
{
    switch (type)
    {
        case PROXY_PROTOCOL_TLV_TYPE_ALPN:
            proxy_protocol_parse_string_tlv(ppi, &ppi->alpn, "ALPN", len, value);
            break;

        case PROXY_PROTOCOL_TLV_TYPE_AUTHORITY:
            proxy_protocol_parse_string_tlv(ppi, &ppi->authority, "AUTHORITY", len, value);
            break;

        case PROXY_PROTOCOL_TLV_TYPE_CRC32C:
            proxy_protocol_parse_crc32c_tlv(len, value);
            break;

        case PROXY_PROTOCOL_TLV_TYPE_NOOP:
            break;

        case PROXY_PROTOCOL_TLV_TYPE_UNIQUE_ID:
            proxy_protocol_parse_uid_tlv(ppi, len, value);
            break;

        case PROXY_PROTOCOL_TLV_TYPE_SSL:
            proxy_protocol_parse_ssl_tlv(ppi, len, value);
            break;

        case PROXY_PROTOCOL_TLV_SUBTYPE_SSL_VERSION:
            proxy_protocol_parse_string_tlv(ppi, &ppi->ssl_version, "SSL_VERSION", len, value);
            break;

        case PROXY_PROTOCOL_TLV_SUBTYPE_SSL_CN:
            proxy_protocol_parse_string_tlv(ppi, &ppi->ssl_cn, "SSL_CN", len, value);
            break;

        case PROXY_PROTOCOL_TLV_SUBTYPE_SSL_CIPHER:
            proxy_protocol_parse_string_tlv(ppi, &ppi->ssl_cipher, "SSL_CIPHER", len, value);
            break;

        case PROXY_PROTOCOL_TLV_SUBTYPE_SSL_SIG_ALG:
            proxy_protocol_parse_string_tlv(ppi, &ppi->ssl_sig_alg, "SSL_SIG_ALG", len, value);
            break;

        case PROXY_PROTOCOL_TLV_SUBTYPE_SSL_KEY_ALG:
            proxy_protocol_parse_string_tlv(ppi, &ppi->ssl_key_alg, "SSL_KEY_ALG", len, value);
            break;

        case PROXY_PROTOCOL_TLV_TYPE_NETNS:
            proxy_protocol_parse_string_tlv(ppi, &ppi->netns, "NETNS", len, value);
            break;

        default:
            msg(M_NONFATAL, "PROXY protocol v2: unknown TLV type 0x%02x", type);
            break;
    }
}

/*
 * Parse the TLVs in the PROXY protocol v2 header.
 *
 * @param ppi - The proxy protocol info structure to store the parsed data.
 * @param buf - The buffer containing the TLVs.
 * @param buf_len - The length of the buffer.
 *
 * @return - The number of bytes parsed or -1 if an error occurred.
 */
int
proxy_protocol_parse_tlvs(struct proxy_protocol_info *ppi, const uint8_t *buf,
                          const int buf_len)
{
    const uint8_t *end = buf + buf_len;
    const uint8_t *start = buf;

    ppi->gc = gc_new();
    while (buf < end && parsing_state == PROXY_PROTOCOL_PARSING_STATE_OK)
    {
        const struct proxy_protocol_tlv *tlv = (const struct proxy_protocol_tlv *)buf;
        uint16_t tlv_len = (tlv->length_hi << 8) | tlv->length_lo;
        if (buf + sizeof(*tlv) + tlv_len > end)
        {
            msg(M_NONFATAL, "PROXY protocol v2: TLV length exceeds buffer size");
            return -1;
        }
        proxy_protocol_parse_tlv(ppi, tlv->type, tlv_len, tlv->value);
        buf += sizeof(*tlv) + tlv_len;
    }
    return (int)(buf - start);
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
                int pos = proxy_protocol_parse_v2(ppi);
                if (parsing_state == PROXY_PROTOCOL_PARSING_STATE_IGNORE)
                {
                    msg(M_DEBUG, "PROXY protocol v2: ignoring header");
                    return true;
                }
                else if (parsing_state == PROXY_PROTOCOL_PARSING_STATE_INVALID)
                {
                    return false;
                }

                if (pos < header_len) /* there's extra TLV data to parse */
                {
                    pos += proxy_protocol_parse_tlvs(ppi, (uint8_t *)(&header) + pos,
                                                     header_len - pos);
                    if (parsing_state == PROXY_PROTOCOL_PARSING_STATE_INVALID)
                    {
                        return false;
                    }
                    if (pos < header_len)
                    {
                        msg(M_NONFATAL, "PROXY protocol v2: could not correclty parse TLV data");
                    }
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
