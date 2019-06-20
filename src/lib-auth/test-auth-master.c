/* Copyright (c) 2019 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "auth-master.h"
#include "net.h"
#include "test-common.h"
#include "str.h"

static void test_auth_user_info_export(void)
{
	string_t *str;
	struct auth_user_info info;

	i_zero(&info);

	test_begin("auth_user_info_export()");

	/* Setup info for auth_user_info_export call where the
	 * resulting auth request string should contain all
	 * real_ variables. */
	test_assert(net_addr2ip("192.168.1.1", &info.local_ip) == 0);
	test_assert(net_addr2ip("192.23.42.9", &info.real_local_ip) == 0);
	test_assert(net_addr2ip("10.42.3.223", &info.remote_ip) == 0);
	test_assert(net_addr2ip("192.168.1.2", &info.real_remote_ip) == 0);
	info.local_port = 57035;
	info.remote_port = 53075;
	info.real_remote_port = 64385;
	info.real_local_port = 57391;

	str = t_str_new(128);
	auth_user_info_export(str, &info);

	test_assert(strstr(str_c(str), "real_rip=192.168.1.2") != NULL);
	test_assert(strstr(str_c(str), "real_lip=192.23.42.9") != NULL);
	test_assert(strstr(str_c(str), "rip=10.42.3.223") != NULL);
	test_assert(strstr(str_c(str), "lip=192.168.1.1") != NULL);
	test_assert(strstr(str_c(str), "real_rport=64385") != NULL);
	test_assert(strstr(str_c(str), "rport=53075") != NULL);
	test_assert(strstr(str_c(str), "real_lport=57391") != NULL);
	test_assert(strstr(str_c(str), "lport=57035") != NULL);

	/* Setup info for auth_user_info_export call where the
	 * resulting auth request string should not contain any
	 * real_ variables. */
	test_assert(net_addr2ip("10.42.3.223", &info.real_remote_ip) == 0);
	test_assert(net_addr2ip("192.168.1.1", &info.real_local_ip) == 0);
	info.real_remote_port = 53075;
	info.real_local_port = 57035;

	str_truncate(str, 0);
	auth_user_info_export(str, &info);

	test_assert(strstr(str_c(str), "rip=10.42.3.223") != NULL);
	test_assert(strstr(str_c(str), "lip=192.168.1.1") != NULL);
	test_assert(strstr(str_c(str), "lport=57035") != NULL);
	test_assert(strstr(str_c(str), "rport=53075") != NULL);
	/* The following fields should not be part of the string as
	 * they are matching with their non-real counterparts */
	test_assert(strstr(str_c(str), "real_lport") == NULL);
	test_assert(strstr(str_c(str), "real_rport") == NULL);
	test_assert(strstr(str_c(str), "real_rip") == NULL);
	test_assert(strstr(str_c(str), "real_lip") == NULL);

	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_auth_user_info_export,
		NULL
	};
	return test_run(test_functions);
}
