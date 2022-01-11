/* Copyright (c) 2021 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "test-common.h"
#include "ostream.h"
#include "str.h"
#include "sort.h"
#include "connect-limit.h"

static guid_128_t session1_guid = {
	0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xf1
};
#define SESSION1_HEX "100000000000000000000000000000f1"
static guid_128_t session2_guid = {
	0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xf2
};
#define SESSION2_HEX "200000000000000000000000000000f2"
static guid_128_t session3_guid = {
	0x30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xf3
};
#define SESSION3_HEX "300000000000000000000000000000f3"

static void
test_session_dump(struct connect_limit *limit, const char *expected_altnames,
		  const char *expected_dump)
{
	string_t *str = str_new(default_pool, 128);
	struct ostream *output = o_stream_create_buffer(str);

	connect_limit_dump(limit, output);
	if (str_len(str) == 1) {
		test_assert_strcmp("", expected_dump);
		o_stream_destroy(&output);
		str_free(&str);
		return;
	}

	/* check the alt usernames header */
	const char *p = strchr(str_c(str), '\n');
	if (p == NULL) {
		test_assert(str_len(str) == 0);
		test_assert_strcmp(expected_altnames, "");
	} else {
		test_assert_strcmp(expected_altnames,
				   t_strndup(str_c(str), p - str_c(str)));
		str_delete(str, 0, p - str_c(str) + 1);
	}

	/* The output comes from hash table, so the order isn't stable.
	   Sort the lines so we can test it. */
	const char **lines = t_strsplit(str_c(str), "\n");
	unsigned int lines_count = str_array_length(lines);
	i_qsort(lines, lines_count, sizeof(const char *), i_strcmp_p);

	string_t *new_str = str_new(default_pool, str_len(str));
	/* the output ends with \n\n and they're sorted first */
	i_assert(lines_count >= 2);
	i_assert(lines[0][0] == '\0');
	i_assert(lines[1][0] == '\0');
	for (unsigned int i = 2; i < lines_count; i++) {
		str_append(new_str, lines[i]);
		str_append_c(new_str, '\n');
	}
	test_assert_strcmp(str_c(new_str), expected_dump);
	str_free(&new_str);

	o_stream_destroy(&output);
	str_free(&str);
}

static void test_connect_limit(void)
{
	struct connect_limit *limit;

	test_begin("connect limit");
	limit = connect_limit_init();

	/* first key */
	struct connect_limit_key key = {
		.username = "user1",
		.service = "service1",
	};
	const char *const alt_usernames1[] = {
		"altkey1", "altvalueA",
		"altkey2", "altvalueB",
		NULL
	};
	struct ip_addr dest_ip;
	i_zero(&dest_ip);
	test_assert(net_addr2ip("1.2.3.4", &key.ip) == 0);
	connect_limit_connect(limit, 501, &key, session1_guid, KICK_TYPE_NONE,
			      &dest_ip, alt_usernames1);
#define TEST_SESSION1_STR "501\tuser1\tservice1\t1.2.3.4\t"SESSION1_HEX"\t\taltvalueA\taltvalueB\n"
	test_session_dump(limit, "altkey1\taltkey2", TEST_SESSION1_STR);
	test_assert(connect_limit_lookup(limit, &key) == 1);

	/* same userip and pid */
	struct connect_limit_key key2 = {
		.username = "user1",
		.service = "service1",
	};
	const char *const alt_usernames2[] = {
		"altkey1", "altvalueA",
		"altkey2", "altvalueC",
		"altkey3", "altvalueA",
		NULL
	};
	test_assert(net_addr2ip("1.2.3.4", &key2.ip) == 0);
	i_zero(&dest_ip);
	connect_limit_connect(limit, 501, &key2, session2_guid, KICK_TYPE_NONE,
			      &dest_ip, alt_usernames2);
#define TEST_SESSION2_STR "501\tuser1\tservice1\t1.2.3.4\t"SESSION2_HEX"\t\taltvalueA\taltvalueC\taltvalueA\n"
	test_session_dump(limit, "altkey1\taltkey2\taltkey3",
			  TEST_SESSION1_STR TEST_SESSION2_STR);
	test_assert(connect_limit_lookup(limit, &key) == 2);

	/* different user */
	struct connect_limit_key key3 = {
		.username = "user2",
		.service = "service2",
	};
	const char *const alt_usernames3[] = {
		"altkey1", "altvalueA",
		"altkey2", "altvalueC",
		"altkey4", "altvalueD",
		NULL
	};
	test_assert(net_addr2ip("4.3.2.1", &key3.ip) == 0);
	test_assert(net_addr2ip("1.0.0.2", &dest_ip) == 0);
	connect_limit_connect(limit, 600, &key3, session3_guid, KICK_TYPE_SIGNAL,
			      &dest_ip, alt_usernames3);
#define TEST_SESSION3_STR "600\tuser2\tservice2\t4.3.2.1\t"SESSION3_HEX"\t1.0.0.2\taltvalueA\taltvalueC\t\taltvalueD\n"
	test_session_dump(limit, "altkey1\taltkey2\taltkey3\taltkey4",
			  TEST_SESSION1_STR TEST_SESSION2_STR TEST_SESSION3_STR);
	test_assert(connect_limit_lookup(limit, &key) == 2);
	test_assert(connect_limit_lookup(limit, &key3) == 0);

	/* duplicate conn-guid */
	struct connect_limit_key key4 = {
		.username = "user3",
		.service = "service3",
	};
	test_assert(net_addr2ip("4.3.2.1", &key4.ip) == 0);
	test_assert(net_addr2ip("1.0.0.3", &dest_ip) == 0);
	test_expect_error_string("connect limit: connection for duplicate connection GUID "SESSION2_HEX" (pid=501 -> 600, user=user1 -> user3, service=service1 -> service3, ip=1.2.3.4 -> 4.3.2.1, dest_ip= -> 1.0.0.3)");
	connect_limit_connect(limit, 600, &key4, session2_guid, KICK_TYPE_SIGNAL,
			      &dest_ip, alt_usernames3);
	test_expect_no_more_errors();
	test_session_dump(limit, "altkey1\taltkey2\taltkey3\taltkey4",
			  TEST_SESSION1_STR TEST_SESSION2_STR TEST_SESSION3_STR);

	/* test user iteration for user1 */
	struct connect_limit_iter *iter =
		connect_limit_iter_begin(limit, "user1", NULL);
	struct connect_limit_iter_result iter_result;
	test_assert(connect_limit_iter_next(iter, &iter_result));
	test_assert(iter_result.pid == 501 &&
		    strcmp(iter_result.service, "service1") == 0 &&
		    guid_128_cmp(iter_result.conn_guid, session1_guid) == 0 &&
		    iter_result.kick_type == KICK_TYPE_NONE);
	test_assert(connect_limit_iter_next(iter, &iter_result));
	test_assert(iter_result.pid == 501 &&
		    strcmp(iter_result.service, "service1") == 0 &&
		    guid_128_cmp(iter_result.conn_guid, session2_guid) == 0 &&
		    iter_result.kick_type == KICK_TYPE_NONE);
	test_assert(!connect_limit_iter_next(iter, &iter_result));
	connect_limit_iter_deinit(&iter);

	/* test user iteration for user2 */
	iter = connect_limit_iter_begin(limit, "user2", NULL);
	test_assert(connect_limit_iter_next(iter, &iter_result));
	test_assert(iter_result.pid == 600 &&
		    strcmp(iter_result.service, "service2") == 0 &&
		    guid_128_cmp(iter_result.conn_guid, session3_guid) == 0 &&
		    iter_result.kick_type == KICK_TYPE_SIGNAL);
	test_assert(!connect_limit_iter_next(iter, &iter_result));
	connect_limit_iter_deinit(&iter);

	/* test user iteration for nonexistent user3 */
	iter = connect_limit_iter_begin(limit, "user3", NULL);
	test_assert(!connect_limit_iter_next(iter, &iter_result));
	connect_limit_iter_deinit(&iter);

	/* test alt username iteration */
	iter = connect_limit_iter_begin_alt_username(limit,
			"altkey1", "altvalueA", NULL);
	test_assert(connect_limit_iter_next(iter, &iter_result));
	test_assert(iter_result.pid == 501 &&
		    strcmp(iter_result.service, "service1") == 0 &&
		    guid_128_cmp(iter_result.conn_guid, session1_guid) == 0 &&
		    iter_result.kick_type == KICK_TYPE_NONE);
	test_assert(connect_limit_iter_next(iter, &iter_result));
	test_assert(iter_result.pid == 501 &&
		    strcmp(iter_result.service, "service1") == 0 &&
		    guid_128_cmp(iter_result.conn_guid, session2_guid) == 0 &&
		    iter_result.kick_type == KICK_TYPE_NONE);
	test_assert(connect_limit_iter_next(iter, &iter_result));
	test_assert(iter_result.pid == 600 &&
		    strcmp(iter_result.service, "service2") == 0 &&
		    guid_128_cmp(iter_result.conn_guid, session3_guid) == 0 &&
		    iter_result.kick_type == KICK_TYPE_SIGNAL);
	test_assert(!connect_limit_iter_next(iter, &iter_result));
	connect_limit_iter_deinit(&iter);

	/* disconnect a single session */
	connect_limit_disconnect(limit, 600, &key3, session3_guid);
	test_session_dump(limit, "altkey1\taltkey2\taltkey3\taltkey4",
			  TEST_SESSION1_STR TEST_SESSION2_STR);
	test_assert(connect_limit_lookup(limit, &key) == 2);
	test_assert(connect_limit_lookup(limit, &key3) == 0);

	/* disconnect all sessions from a process */
	connect_limit_disconnect_pid(limit, 501);
	test_session_dump(limit, "altkey1\taltkey2\taltkey3\taltkey4", "");
	test_assert(connect_limit_lookup(limit, &key3) == 0);

	connect_limit_deinit(&limit);
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_connect_limit,
		NULL
	};
	return test_run(test_functions);
}
