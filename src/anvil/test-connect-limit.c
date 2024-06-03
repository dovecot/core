/* Copyright (c) 2021 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "test-common.h"
#include "istream.h"
#include "ostream.h"
#include "llist.h"
#include "str.h"
#include "strescape.h"
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

struct test_session {
	struct test_session *prev, *next;

	pid_t pid;
	struct connect_limit_key key;
	guid_128_t guid;
	struct ip_addr dest_ip;
	const char *alt_usernames[3*2 + 1];
	bool found;
};

static void
test_session_disconnect(struct connect_limit *limit,
			struct test_session **test_sessions,
			unsigned int *test_session_count)
{
	struct test_session *session;
	unsigned int i, elem = i_rand_limit(*test_session_count);

	for (i = 0, session = *test_sessions; i < elem; i++)
		session = session->next;

	DLLIST_REMOVE(test_sessions, session);
	*test_session_count -= 1;

	connect_limit_disconnect(limit, session->pid,
				 &session->key, session->guid);
}

static void
test_session_disconnect_pid(struct connect_limit *limit, pid_t pid,
			    struct test_session **test_sessions,
			    unsigned int *test_session_count)
{
	struct test_session *session, *next;

	for (session = *test_sessions; session != NULL; session = next) {
		next = session->next;
		if (session->pid == pid) {
			DLLIST_REMOVE(test_sessions, session);
			*test_session_count -= 1;
		}
	}

	connect_limit_disconnect_pid(limit, pid);
}

static struct test_session *
test_session_find(struct test_session *test_sessions, const guid_128_t guid)
{
	struct test_session *session = test_sessions;

	for (; session != NULL; session = session->next) {
		if (guid_128_equals(session->guid, guid))
			return session;
	}
	return NULL;
}

static void test_sessions_compare(struct connect_limit *limit,
				  struct test_session *test_sessions)
{
	string_t *str = str_new(default_pool, 10240);
	struct ostream *output = o_stream_create_buffer(str);
	o_stream_set_no_error_handling(output, TRUE);
	connect_limit_dump(limit, output);
	o_stream_unref(&output);

	struct istream *input =
		i_stream_create_from_data(str_data(str), str_len(str));
	/* check that all alt header names look valid */
	const char *const *alt_headers =
		t_strsplit_tabescaped(i_stream_next_line(input));
	for (unsigned int i = 0; alt_headers[i] != NULL; i++)
		test_assert_idx(str_begins_with(alt_headers[i], "altfield"), i);

	const char *line;
	while ((line = i_stream_next_line(input)) != NULL) {
		if (line[0] == '\0')
			break;
		/* pid, username, service, ip, conn_guid, dest_ip, alt_users */
		const char *const *args = t_strsplit_tabescaped(line);
		test_assert(str_array_length(args) >= 6);

		guid_128_t guid;
		test_assert(guid_128_from_string(args[4], guid) == 0);
		struct test_session *session =
			test_session_find(test_sessions, guid);
		i_assert(session != NULL);

		test_assert(!session->found);
		session->found = TRUE;

		pid_t pid;
		test_assert(str_to_pid(args[0], &pid) == 0);
		test_assert(pid == session->pid);
		test_assert_strcmp(args[1], session->key.username);
		test_assert_strcmp(args[2], session->key.service);
		struct ip_addr ip, dest_ip;
		test_assert(net_addr2ip(args[3], &ip) == 0);
		test_assert(net_ip_cmp(&ip, &session->key.ip) == 0);
		if (args[5][0] == '\0')
			test_assert(session->dest_ip.family == 0);
		else {
			test_assert(net_addr2ip(args[5], &dest_ip) == 0);
			test_assert(net_ip_cmp(&dest_ip, &session->dest_ip) == 0);
		}

		args += 6;
		unsigned int i, j, alt_username_count = 0;
		for (i = 0; args[i] != NULL; i++) {
			if (args[i][0] == '\0')
				continue;

			for (j = 0; session->alt_usernames[j] != NULL; j += 2) {
				i_assert(alt_headers[i] != NULL);
				if (strcmp(session->alt_usernames[j],
					   alt_headers[i]) == 0)
					break;
			}
			test_assert(session->alt_usernames[j] != NULL);
			test_assert_strcmp(session->alt_usernames[j + 1], args[i]);
			alt_username_count++;
		}
		test_assert(str_array_length(session->alt_usernames) / 2 ==
			    alt_username_count);
	}

	struct test_session *session = test_sessions;
	for (; session != NULL; session = session->next) {
		test_assert(session->found);
		session->found = FALSE;
	}

	i_stream_unref(&input);
	str_free(&str);
}

static void test_connect_limit_random(void)
{
	struct connect_limit *limit;
	struct test_session *test_sessions = NULL;
	unsigned int test_session_count = 0;

	test_begin("connect limit random");
	limit = connect_limit_init();

	pool_t pool = pool_alloconly_create("test", 1024*400);
	for (unsigned int i = 0; i < 1000; i++) {
		struct test_session *session =
			p_new(pool, struct test_session, 1);
		session->pid = i_rand_minmax(1, 1000);
		session->key.username =
			p_strdup_printf(pool, "user%d", i_rand_limit(10000));
		session->key.service =
			p_strdup_printf(pool, "service%d", i_rand_limit(100));
		session->key.ip.family = AF_INET;
		session->key.ip.u.ip4.s_addr = i_rand_minmax(1, INT_MAX);
		guid_128_generate(session->guid);

		test_session_count++;
		DLLIST_PREPEND(&test_sessions, session);

		if (i_rand_limit(10) == 0) {
			session->dest_ip.family = AF_INET;
			session->dest_ip.u.ip4.s_addr = i_rand_minmax(1, INT_MAX);
		}

		unsigned int j, alt_username_count =
			i_rand_limit(N_ELEMENTS(session->alt_usernames)/2);
		unsigned int altidx = 0;
		for (j = 0; j < alt_username_count; j++) {
			altidx += 1 + i_rand_limit(3);
			session->alt_usernames[j * 2] =
				p_strdup_printf(pool, "altfield%d", altidx);
			session->alt_usernames[j * 2 + 1] =
				p_strdup_printf(pool, "altuser%d",
						i_rand_limit(10000));
		}

		connect_limit_connect(limit, session->pid, &session->key,
				      session->guid, KICK_TYPE_NONE,
				      &session->dest_ip, session->alt_usernames);
		while (test_session_count > 0 &&
		       i_rand_limit(3) == 0) {
			test_session_disconnect(limit, &test_sessions,
						&test_session_count);
		}
		if (i_rand_limit(50) == 0 && test_sessions != NULL) {
			test_session_disconnect_pid(limit, test_sessions->pid,
						    &test_sessions,
						    &test_session_count);
		}
		if (i_rand_limit(500) == 0)
			test_sessions_compare(limit, test_sessions);
	}
	test_sessions_compare(limit, test_sessions);

	connect_limit_deinit(&limit);
	pool_unref(&pool);
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_connect_limit,
		test_connect_limit_random,
		NULL
	};
	return test_run(test_functions);
}
