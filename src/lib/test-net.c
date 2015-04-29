/* Copyright (c) 2007-2015 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "net.h"

struct test_net_is_in_network_input {
	const char *ip;
	const char *net;
	unsigned int bits;
	bool ret;
};

static void test_net_is_in_network(void)
{
	static struct test_net_is_in_network_input input[] = {
		{ "1.2.3.4", "1.2.3.4", 32, TRUE },
		{ "1.2.3.4", "1.2.3.3", 32, FALSE },
		{ "1.2.3.4", "1.2.3.5", 32, FALSE },
		{ "1.2.3.4", "1.2.2.4", 32, FALSE },
		{ "1.2.3.4", "1.1.3.4", 32, FALSE },
		{ "1.2.3.4", "0.2.3.4", 32, FALSE },
		{ "1.2.3.253", "1.2.3.254", 31, FALSE },
		{ "1.2.3.254", "1.2.3.254", 31, TRUE },
		{ "1.2.3.255", "1.2.3.254", 31, TRUE },
		{ "1.2.3.255", "1.2.3.0", 24, TRUE },
		{ "1.2.255.255", "1.2.254.0", 23, TRUE },
		{ "255.255.255.255", "128.0.0.0", 1, TRUE },
		{ "255.255.255.255", "127.0.0.0", 1, FALSE }
#ifdef HAVE_IPV6
		,
		{ "1234:5678::abcf", "1234:5678::abce", 127, TRUE },
		{ "1234:5678::abcd", "1234:5678::abce", 127, FALSE },
		{ "123e::ffff", "123e::0", 15, TRUE },
		{ "123d::ffff", "123e::0", 15, FALSE }
#endif
	};
	struct ip_addr ip, net_ip;
	unsigned int i;
	bool success;

	test_begin("net_is_in_network()");
	for (i = 0; i < N_ELEMENTS(input); i++) {
		test_assert(net_addr2ip(input[i].ip, &ip) == 0);
		test_assert(net_addr2ip(input[i].net, &net_ip) == 0);
		success = net_is_in_network(&ip, &net_ip, input[i].bits) ==
			input[i].ret;
		test_out(t_strdup_printf("net_is_in_network(%u)", i), success);
	}
	test_end();
}

static void test_net_ip2addr(void)
{
	struct ip_addr ip;

	test_begin("net_ip2addr()");
	test_assert(net_addr2ip("127.0.0.1", &ip) == 0 &&
		    ip.family == AF_INET &&
		    ip.u.ip4.s_addr == (127 | (1 << 24)));
#ifdef HAVE_IPV6
	test_assert(net_addr2ip("::5", &ip) == 0 &&
		    ip.family == AF_INET6 &&
		    ip.u.ip6.s6_addr[15] == 5);
	test_assert(net_addr2ip("[::5]", &ip) == 0 &&
		    ip.family == AF_INET6 &&
		    ip.u.ip6.s6_addr[15] == 5);
	ip.family = 123;
	test_assert(net_addr2ip("abc", &ip) < 0 &&
		    ip.family == 123);
#endif
	test_end();
}

void test_net(void)
{
	test_net_is_in_network();
	test_net_ip2addr();
}
