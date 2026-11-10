/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "test-auth.h"
#include "net.h"
#include "auth-common.h"
#include "auth-master-connection.h"
#include "test-auth-master.h"

#include <sys/stat.h>

void auth_master_server_connected(int *server_fd, const char *socket)
{
	struct stat st;
	i_zero(&st);
	struct auth *auth = auth_default_protocol();
	int fd = net_accept(*server_fd, NULL, NULL);
	i_assert(fd > 0);
	auth_master_connection_create(auth, fd, socket, &st, FALSE);
}

void auth_master_server_deinit(void)
{
	auth_master_connections_destroy_all();
}

void test_auth_master_input_hide_secrets(void)
{
	static const struct {
		const char *line;
		const char *hidden;
	} tests[] = {
		{ "USER\t1\tuser\tproxy_pass=x\tquota=1",
		  "USER\t1\tuser\tproxy_pass=<hidden>\tquota=1" },
		{ "PASS\t1\tpass=word\tauth_token=abc\tservice=imap",
		  "PASS\t1\tpass=word\tauth_token=<hidden>\tservice=imap" },
		{ "LIST\tpass=x\tpassword=y\tuser=*",
		  "LIST\tpass=x\tpassword=<hidden>\tuser=*" },
		{ "REQUEST\t1\t2\t3\t0123456789abcdef\tsession=x\tproxy_pass=y",
		  "REQUEST\t1\t2\t3\t<hidden>\tsession=x\tproxy_pass=<hidden>" },
		{ "REQUEST\t1\t2\t3", "REQUEST\t1\t2\t3" },
		{ "CACHE-FLUSH\t1\tproxy_pass=x", NULL },
		{ "CACHE-STATUS\t1\tproxy_pass=x", NULL },
		{ "UNKNOWN\tpassword=x\tuser=u",
		  "UNKNOWN\tpassword=<hidden>\tuser=u" },
	};

	test_begin("auth master input hide secrets");
	for (unsigned int i = 0; i < N_ELEMENTS(tests); i++) {
		const char *const *args = t_strsplit(tests[i].line, "\t");
		test_assert_strcmp_idx(auth_master_input_hide_secrets(args),
				       tests[i].hidden != NULL ?
				       tests[i].hidden : tests[i].line, i);
	}
	test_end();
}
