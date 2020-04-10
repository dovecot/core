/* Copyright (c) 2001-2018 Dovecot authors, see the included COPYING file */

/* Unit tests for failure helpers */

#include "test-lib.h"
#include "hostpid.h"
#include "istream.h"
#include "failures.h"

#include <unistd.h>

static int handlers_set_me;

static void test_failures_handler(const struct failure_context *ctx,
				  const char *format ATTR_UNUSED,
				  va_list args ATTR_UNUSED)
{
	handlers_set_me = ctx->type;
}
static void test_get_set_handlers(void)
{
	failure_callback_t *handlers[4];
	test_begin("get_handlers");
	i_get_failure_handlers(handlers, handlers+1, handlers+2, handlers+3);
	test_end();

	test_begin("set_handlers");

	i_set_debug_handler(&test_failures_handler);
	i_debug("If you see this debug, something's gone wrong");
	test_assert(handlers_set_me == LOG_TYPE_DEBUG);
	i_set_debug_handler(handlers[3]);

	i_set_info_handler(&test_failures_handler);
	i_info("If you see this info, something's gone wrong");
	test_assert(handlers_set_me == LOG_TYPE_INFO);
	i_set_info_handler(handlers[2]);

	i_set_error_handler(&test_failures_handler);
	i_warning("If you see this warning, something's gone wrong");
	test_assert(handlers_set_me == LOG_TYPE_WARNING);
	i_error("If you see this error, something's gone wrong");
	test_assert(handlers_set_me == LOG_TYPE_ERROR);
	i_set_error_handler(handlers[1]);

	//i_set_fatal_handler(&test_failures_handler);
	//i_fatal("If you see this fatal, something's gone wrong");
	//test_assert(handlers_set_me == LOG_TYPE_FATAL);
	//i_set_fatal_handler(handlers[0]);

	test_end();
}
static void test_expected(void)
{
	test_begin("expected messages");
	test_expect_errors(1);
	i_warning("deliberate warning - not suppressed");
	test_expect_no_more_errors();
	test_end();
}
static void test_expected_str(void)
{
	test_begin("expected strings in messages");
	test_expect_error_string("be unhappy");
	i_error("deliberate error - suppressed - be unhappy if you see this");
	test_expect_no_more_errors();
	test_end();
}

static bool
internal_line_match(const char *line, const char *prefix, const char *text)
{
	if (line == NULL)
		return FALSE;

	if (line[0] != '\001')
		return FALSE;
	uint8_t type = (uint8_t)line[1];
	if (type != ((LOG_TYPE_DEBUG+1) | 0x80))
		return FALSE;
	line += 2;

	if (!str_begins(line, "123 ", &line))
		return FALSE;

	if (!str_begins(line, prefix, &line))
		return FALSE;

	return strcmp(line, text) == 0;
}

static void test_internal_split(void)
{
	int fd[2];

	test_begin("splitting long internal log lines");

	char long_log_prefix[PIPE_BUF+1];
	memset(long_log_prefix, 'X', sizeof(long_log_prefix)-1);
	long_log_prefix[sizeof(long_log_prefix)-1] = '\0';

#define TEXT10 "tttttttttt"
#define TEXT128 TEXT10 TEXT10 TEXT10 TEXT10 TEXT10 TEXT10 TEXT10 TEXT10 \
	TEXT10 TEXT10 TEXT10 TEXT10 "tttttttt"

	char long_lext[PIPE_BUF*2+1];
	memset(long_lext, 'T', sizeof(long_lext)-1);
	long_lext[sizeof(long_lext)-1] = '\0';

	if (pipe(fd) < 0)
		i_fatal("pipe() failed: %m");
	switch (fork()) {
	case (pid_t)-1:
		i_fatal("fork() failed: %m");
	case 0:
		/* child - log writer */
		if (dup2(fd[1], STDERR_FILENO) < 0)
			i_fatal("dup2() failed: %m");
		i_close_fd(&fd[0]);
		i_close_fd(&fd[1]);

		struct failure_context ctx = {
			.type = LOG_TYPE_DEBUG,
			.log_prefix = long_log_prefix,
		};

		i_set_failure_internal();
		my_pid = "123";
		i_log_type(&ctx, "little text");
		i_log_type(&ctx, TEXT128 TEXT128 TEXT128);
		ctx.log_prefix = "";
		i_log_type(&ctx, "%s", long_lext);
		test_exit(0);
	case 1:
		/* parent - log reader */
		i_close_fd(&fd[1]);
		break;
	}

	alarm(10);
	struct istream *input = i_stream_create_fd(fd[0], SIZE_MAX);

	/* long prefix, little text */
	const char *line = i_stream_read_next_line(input);
	test_assert(internal_line_match(line, long_log_prefix, "little text"));

	/* long prefix, text split to multiple lines */
	for (unsigned int i = 0; i < 3; i++) {
		line = i_stream_read_next_line(input);
		test_assert(internal_line_match(line, long_log_prefix, TEXT128));
	}

	/* no prefix, just lots of text */
	line = i_stream_read_next_line(input);
	long_lext[PIPE_BUF-7] = '\0';
	test_assert(internal_line_match(line, "", long_lext));
	line = i_stream_read_next_line(input);
	test_assert(internal_line_match(line, "", long_lext));
	line = i_stream_read_next_line(input);
	test_assert(internal_line_match(line, "", "TTTTTTTTTTTTTT"));

	i_stream_unref(&input);
	alarm(0);

	test_end();
}

void test_failures(void)
{
	test_get_set_handlers();
	test_expected();
	test_expected_str();
	test_internal_split();
}
