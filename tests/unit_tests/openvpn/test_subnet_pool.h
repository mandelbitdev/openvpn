/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2026 OpenVPN Inc <sales@openvpn.net>
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
#ifndef SUBNET_POOL_TEST_H
#define SUBNET_POOL_TEST_H

/* --subnet-pool tests, run as part of misc_testdriver */

void test_subnet_pool_by_name(void **state);

void test_subnet_pools_check_netmask(void **state);

void test_subnet_pools_check_gateway(void **state);

void test_subnet_pools_check_range(void **state);

void test_subnet_pools_check_overlap(void **state);

void test_subnet_pool6_by_name(void **state);

void test_subnet_pools6_check(void **state);

#endif
