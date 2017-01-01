/* Copyright (c) 2007-2017 Dovecot authors, see the included COPYING file */

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
	static const struct test_net_is_in_network_input input[] = {
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
		{ "255.255.255.255", "127.0.0.0", 1, FALSE },
		{ "1234:5678::abcf", "1234:5678::abce", 127, TRUE },
		{ "1234:5678::abcd", "1234:5678::abce", 127, FALSE },
		{ "123e::ffff", "123e::0", 15, TRUE },
		{ "::ffff:1.2.3.4", "1.2.3.4", 32, TRUE },
		{ "::ffff:1.2.3.4", "1.2.3.3", 32, FALSE },
		{ "::ffff:1.2.3.4", "::ffff:1.2.3.4", 0, FALSE }
	};
	struct ip_addr ip, net_ip;
	unsigned int i;

	test_begin("net_is_in_network()");
	for (i = 0; i < N_ELEMENTS(input); i++) {
		test_assert(net_addr2ip(input[i].ip, &ip) == 0);
		test_assert(net_addr2ip(input[i].net, &net_ip) == 0);
		test_assert_idx(net_is_in_network(&ip, &net_ip, input[i].bits) ==
				input[i].ret, i);
	}
	/* make sure non-IPv4 and non-IPv6 ip_addrs fail */
	test_assert(net_addr2ip("127.0.0.1", &ip) == 0);
	net_ip = ip;
	net_ip.family = 0;
	test_assert(!net_is_in_network(&ip, &net_ip, 0));
	test_assert(!net_is_in_network(&net_ip, &ip, 0));
	test_assert(net_addr2ip("::1", &ip) == 0);
	net_ip = ip;
	net_ip.family = 0;
	test_assert(!net_is_in_network(&ip, &net_ip, 0));
	test_assert(!net_is_in_network(&net_ip, &ip, 0));
	test_end();
}

static void test_net_ip2addr(void)
{
	struct ip_addr ip;

	test_begin("net_ip2addr()");
	test_assert(net_addr2ip("127.0.0.1", &ip) == 0 &&
		    ip.family == AF_INET &&
		    ntohl(ip.u.ip4.s_addr) == (0x7f000001));
	test_assert(net_addr2ip("::5", &ip) == 0 &&
		    ip.family == AF_INET6 &&
		    ip.u.ip6.s6_addr[15] == 5);
	test_assert(net_addr2ip("[::5]", &ip) == 0 &&
		    ip.family == AF_INET6 &&
		    ip.u.ip6.s6_addr[15] == 5);
	ip.family = 123;
	test_assert(net_addr2ip("abc", &ip) < 0 &&
		    ip.family == 123);
	test_end();
}

static void test_net_str2hostport(void)
{
	const char *host;
	in_port_t port;

	test_begin("net_str2hostport()");
	/* [IPv6] */
	test_assert(net_str2hostport("[1::4]", 0, &host, &port) == 0 &&
		    strcmp(host, "1::4") == 0 && port == 0);
	test_assert(net_str2hostport("[1::4]", 1234, &host, &port) == 0 &&
		    strcmp(host, "1::4") == 0 && port == 1234);
	test_assert(net_str2hostport("[1::4]:78", 1234, &host, &port) == 0 &&
		    strcmp(host, "1::4") == 0 && port == 78);
	host = NULL;
	test_assert(net_str2hostport("[1::4]:", 1234, &host, &port) < 0 && host == NULL);
	test_assert(net_str2hostport("[1::4]:0", 1234, &host, &port) < 0 && host == NULL);
	test_assert(net_str2hostport("[1::4]:x", 1234, &host, &port) < 0 && host == NULL);
	/* IPv6 */
	test_assert(net_str2hostport("1::4", 0, &host, &port) == 0 &&
		    strcmp(host, "1::4") == 0 && port == 0);
	test_assert(net_str2hostport("1::4", 1234, &host, &port) == 0 &&
		    strcmp(host, "1::4") == 0 && port == 1234);
	/* host */
	test_assert(net_str2hostport("foo", 0, &host, &port) == 0 &&
		    strcmp(host, "foo") == 0 && port == 0);
	test_assert(net_str2hostport("foo", 1234, &host, &port) == 0 &&
		    strcmp(host, "foo") == 0 && port == 1234);
	test_assert(net_str2hostport("foo:78", 1234, &host, &port) == 0 &&
		    strcmp(host, "foo") == 0 && port == 78);
	host = NULL;
	test_assert(net_str2hostport("foo:", 1234, &host, &port) < 0 && host == NULL);
	test_assert(net_str2hostport("foo:0", 1234, &host, &port) < 0 && host == NULL);
	test_assert(net_str2hostport("foo:x", 1234, &host, &port) < 0 && host == NULL);
	/* edge cases with multiple ':' - currently these don't return errors,
	   but perhaps they should. */
	test_assert(net_str2hostport("foo::78", 1234, &host, &port) == 0 &&
		    strcmp(host, "foo::78") == 0 && port == 1234);
	test_assert(net_str2hostport("::foo:78", 1234, &host, &port) == 0 &&
		    strcmp(host, "::foo:78") == 0 && port == 1234);
	test_assert(net_str2hostport("[::foo]:78", 1234, &host, &port) == 0 &&
		    strcmp(host, "::foo") == 0 && port == 78);
	test_assert(net_str2hostport("[::::]", 1234, &host, &port) == 0 &&
		    strcmp(host, "::::") == 0 && port == 1234);
	test_assert(net_str2hostport("[::::]:78", 1234, &host, &port) == 0 &&
		    strcmp(host, "::::") == 0 && port == 78);
	test_end();
}

void test_net(void)
{
	test_net_is_in_network();
	test_net_ip2addr();
	test_net_str2hostport();
}
