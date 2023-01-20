/* Copyright (c) 2007-2018 Dovecot authors, see the included COPYING file */

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
		{ "::ffff:1.2.3.4", "::ffff:1.2.3.4", 0, FALSE },
		{ "fe80::1%lo", "fe80::%lo", 8, TRUE },
		{ "fe80::1%lo", "fe80::", 8, TRUE },
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

	/* make sure a changed scope_id won't match */
	test_assert(net_addr2ip("fe80::1%lo", &ip) == 0);
	test_assert(net_addr2ip("fe80::1%lo", &net_ip) == 0);
	test_assert(net_is_in_network(&ip, &net_ip, 1));
	net_ip.scope_id++;
	test_assert(!net_is_in_network(&ip, &net_ip, 1));
	test_end();
}

static void test_net_ip2addr(void)
{
	struct ip_addr ip;

	test_begin("net_ip2addr()");
	test_assert(net_addr2ip("127.0.0.1", &ip) == 0 &&
		    ip.family == AF_INET &&
		    ntohl(ip.u.ip4.s_addr) == (0x7f000001));
	test_assert(net_addr2ip("2130706433", &ip) == 0 &&
		    ip.family == AF_INET &&
		    ntohl(ip.u.ip4.s_addr) == (0x7f000001));
	test_assert(strcmp(net_ip2addr(&ip), "127.0.0.1") == 0);
	test_assert(net_addr2ip("255.254.253.252", &ip) == 0 &&
		    ip.family == AF_INET &&
		    ntohl(ip.u.ip4.s_addr) == (0xfffefdfc));
	test_assert(strcmp(net_ip2addr(&ip), "255.254.253.252") == 0);
	test_assert(net_addr2ip("::5", &ip) == 0 &&
		    ip.family == AF_INET6 &&
		    ip.u.ip6.s6_addr[15] == 5);
	test_assert(strcmp(net_ip2addr(&ip), "::5") == 0);
	test_assert(net_addr2ip("[::5]", &ip) == 0 &&
		    ip.family == AF_INET6 &&
		    ip.u.ip6.s6_addr[15] == 5);
	test_assert(strcmp(net_ip2addr(&ip), "::5") == 0);
	ip.family = 123;
	test_assert(net_addr2ip("abc", &ip) < 0 &&
		    ip.family == 123);
	test_assert(net_addr2ip("fe80::1", &ip) == 0);
	test_assert_strcmp(net_ip2addr(&ip), "fe80::1");
	test_assert(net_addr2ip("fe80::1%lo", &ip) == 0);
	test_assert_strcmp(net_ip2addr(&ip), "fe80::1%lo");
	test_end();
}

static void test_net_str2hostport(void)
{
	const char *host;
	in_port_t port;

	test_begin("net_str2hostport()");
	/* IPv4  */
	test_assert(net_str2hostport("127.0.0.1", 0, &host, &port) == 0 &&
		    strcmp(host, "127.0.0.1") == 0 && port == 0);
	test_assert(net_str2hostport("127.0.0.1", 143, &host, &port) == 0 &&
		    strcmp(host, "127.0.0.1") == 0 && port == 143);
	test_assert(net_str2hostport("127.0.0.1:993", 143, &host, &port) == 0 &&
		    strcmp(host, "127.0.0.1") == 0 && port == 993);
	test_assert(net_str2hostport("127.0.0.1:143", 0, &host, &port) == 0 &&
		    strcmp(host, "127.0.0.1") == 0 && port == 143);
	test_assert(net_str2hostport("*", 0, &host, &port) == 0 &&
		    strcmp(host, "*") == 0 && port == 0);
	test_assert(net_str2hostport("*:143", 0, &host, &port) == 0 &&
		    strcmp(host, "*") == 0 && port == 143);
	/* [IPv6] */
	test_assert(net_str2hostport("::", 0, &host, &port) == 0 &&
		    strcmp(host, "::") == 0 && port == 0);
	test_assert(net_str2hostport("[::]", 0, &host, &port) == 0 &&
		    strcmp(host, "::") == 0 && port == 0);
	test_assert(net_str2hostport("[::]:143", 0, &host, &port) == 0 &&
		    strcmp(host, "::") == 0 && port == 143);
	test_assert(net_str2hostport("[::]", 143, &host, &port) == 0 &&
		    strcmp(host, "::") == 0 && port == 143);
	test_assert(net_str2hostport("[::]:993", 143, &host, &port) == 0 &&
		    strcmp(host, "::") == 0 && port == 993);
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

static void test_net_unix_long_paths(void)
{
#ifdef ENAMETOOLONG
	int long_errno = ENAMETOOLONG;
#else
	int long_errno = EOVERFLOW;
#endif

	test_begin("net_*_unix() - long paths");

	char path[PATH_MAX];
	memset(path, 'x', sizeof(path)-1);
	path[sizeof(path)-1] = '\0';

	test_assert(net_listen_unix(path, 1) == -1);
	test_assert(errno == long_errno);

	test_assert(net_connect_unix(path) == -1);
	test_assert(errno == long_errno);

	test_end();
}

static void test_net_addr2ip(void)
{
	const struct {
		const char *addr;
		bool valid;
		sa_family_t af;
	} test_cases[] = {
		/* Potential IPv4 */
		{ "127.0.0.1", TRUE, AF_INET },
		{ "256.256.256.256", FALSE, AF_UNSPEC },
		{ "1.2.3.4", TRUE, AF_INET },
		{ "0.0.0.0", TRUE, AF_INET },
		{ "1", TRUE, AF_INET },
		{ "127.0.0.1:53", FALSE, AF_UNSPEC },
		{ "16909060", TRUE, AF_INET },
		/* Potential IPv6 */
		{ "::1", TRUE, AF_INET6 },
		{ "2001:6e8::1", TRUE, AF_INET6 },
		{ "::ffff:1.2.3.4", TRUE, AF_INET6 },
		{ "fe80:0:0:0:5054:ff:fe0a:fdb3", TRUE, AF_INET6 },
		{ "fe80:0000:0000:0000:5054:00ff:fe0a:fdb3", TRUE, AF_INET6 },
		{ "fe80::1%lo", TRUE, AF_INET6 },
		{ "[fe80::1]", TRUE, AF_INET6 },
		{ "[fe80::1]:80", FALSE, AF_UNSPEC },
		/* garbages */
		{ "hippo", FALSE, AF_UNSPEC },
		{ "16:34", FALSE, AF_UNSPEC },
	};
	test_begin("net_addr2ip()");
	for (size_t i = 0; i < N_ELEMENTS(test_cases); i++) {
		struct ip_addr ip;
		ip.family = AF_UNSPEC;
		bool valid = net_addr2ip(test_cases[i].addr, &ip) == 0;
		test_assert_idx(valid == test_cases[i].valid, i);
		test_assert_idx(ip.family == test_cases[i].af, i);
	}
	test_end();
}

void test_net(void)
{
	test_net_is_in_network();
	test_net_ip2addr();
	test_net_addr2ip();
	test_net_str2hostport();
	test_net_unix_long_paths();
}
