/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2026 OpenVPN Inc <sales@openvpn.net>
 *  Copyright (C) 2010-2026 Sentyron B.V. <openvpn@sentyron.com>
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

#ifndef OPTIONS_UTIL_H_
#define OPTIONS_UTIL_H_

#include "options.h"

const char *parse_auth_failed_temp(struct options *o, const char *reason);


/** Checks if the string is a valid integer by checking if it can be
 *  converted to an integer */
bool valid_integer(const char *str, bool positive);

/**
 * Converts a str to a positive number if the string represents a postive
 * integer number. Otherwise print a warning with msglevel and return 0
 */
int positive_atoi(const char *str, msglvl_t msglevel);

/**
 * Converts a str to an integer if the string can be represented as an
 * integer number and is >= 0.
 * The integer is stored in \p value.
 * On error, print a warning with \p msglevel using \p name. \p value is
 * not changed on error.
 *
 * @return \c true if the integer has been parsed and stored in value, \c false otherwise
 */
bool positive_atoll(const char *str, int64_t *value, const char *name, msglvl_t msglevel);

/**
 * Converts a str to an integer if the string can be represented as an
 * integer number. Otherwise print a warning with \p msglevel and return 0
 */
int atoi_warn(const char *str, msglvl_t msglevel);

/**
 * Converts a str to an integer if the string can be represented as an
 * integer number and is between \p min and \p max.
 * The integer is stored in \p value.
 * On error, print a warning with \p msglevel using \p name. \p value is
 * not changed on error.
 *
 * @return \c true if the integer has been parsed and stored in value, \c false otherwise
 */
bool atoi_constrained(const char *str, int *value, const char *name, int min, int max,
                      msglvl_t msglevel);

/**
 * Filter an option line by all pull filters.
 *
 * If a match is found, the line is modified depending on
 * the filter type, and returns true. If the filter type is
 * reject, SIGUSR1 is triggered and the return value is false.
 * In that case the caller must end the push processing.
 */
bool apply_pull_filter(const struct options *o, char *line);

/**
 * @brief Checks the formatting and validity of options inside push-update messages.
 *
 * This function is used to validate and process options
 * in push-update messages. It performs the following checks:
 * - Determines if the options are updatable.
 * - Checks for the presence of the `-` flag, which indicates that the option
 *   should be removed.
 * - Checks for the `?` flag, which marks the option as optional and suppresses
 *   errors if the client cannot update it.
 * - Increase the value pointed by 'i' when we encounter the `'-'` and `'?'` flags
 *   after validating them and updating the appropriate flags in the `flags` variable.
 * - `-?option`, `-option`, `?option` are valid formats, `?-option` is not a valid format.
 * - If the flags and the option are not consecutive, the option is invalid:
 *   `- ?option`, `-? option`, `- option` are invalid formats.
 *
 * @param line A pointer to an option string. This string is the option being validated.
 * @param i A pointer to an integer that represents the current index in the `line` string.
 * @param flags A pointer where flags will be stored:
 *              - `PUSH_OPT_TO_REMOVE`: Set if the `-` flag is present.
 *              - `PUSH_OPT_OPTIONAL`: Set if the `?` flag is present.
 *
 * @return true if the flags and option combination are valid.
 * @return false if:
 *         - The `-` and `?` flags are not formatted correctly.
 *         - The `line` parameter is empty or `NULL`.
 *         - The `?` flag is absent and the option is not updatable.
 */
bool check_push_update_option_flags(char *line, int *i, unsigned int *flags);

/**
 * Convert option parameters whose first IPv4 parameter may be in CIDR notation.
 *
 * The input tokens are read from \p p and the normalized output tokens are
 * written to \p normalized.
 *
 * When \p p[network_idx] is in CIDR form (for example, ``10.8.0.0/24``), this
 * function:
 * - splits the network and prefix length,
 * - converts the prefix length to dotted-quad netmask,
 * - writes ``network`` and ``netmask`` into ``normalized[network_idx]`` and
 *   ``normalized[network_idx + 1]``,
 * - shifts remaining parameters one position to preserve legacy
 *   ``network netmask ...`` layout.
 *
 * When \p p[network_idx] is not CIDR, \p normalized receives \p p unchanged
 * for the copied range (indices ``0..max_idx`` until ``NULL``), and no
 * conversion is applied.
 *
 * @param p Input option tokens (argv-style, NULL-terminated).
 * @param network_idx Index in \p p of the parameter that may contain CIDR.
 * @param max_idx Maximum parameter index to normalize.
 * @param normalized Output token array receiving normalized parameters
 *                   (argv-style, NULL-terminated in CIDR case).
 * @param gc GC arena used for converted string allocations.
 *
 * @return 0 when no CIDR notation was present and no conversion was needed.
 * @return 1 when CIDR notation was present and conversion was applied.
 * @return -EINVAL on malformed CIDR input.
 */
int convert_ipv4_cidr_parms(char *p[], int network_idx, int max_idx,
                            char *normalized[], struct gc_arena *gc);

#endif /* ifndef OPTIONS_UTIL_H_ */
