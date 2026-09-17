/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "str.h"
#include "ostream.h"
#include "test-common.h"
#include "doveadm-print.h"
#include "doveadm-print-private.h"

/* The binaries define this table in their main.c; the test needs only the
   server driver. */
const struct doveadm_print_vfuncs *doveadm_print_vfuncs_all[] = {
	&doveadm_print_server_vfuncs,
	NULL
};

/* doveadm-server keeps one process alive for many commands. The server print
   driver must therefore start every command with a clean header state, or a
   one-column row is no longer recognized as complete and stays buffered until
   deinit. */
static void test_doveadm_print_server_header_reset(void)
{
	string_t *out = str_new(default_pool, 128);
	unsigned int i;

	test_begin("doveadm-print-server header state reset between commands");
	doveadm_print_ostream = o_stream_create_buffer(out);

	for (i = 0; i < 3; i++) {
		str_truncate(out, 0);
		doveadm_print_init(DOVEADM_PRINT_TYPE_SERVER);
		doveadm_print_header_simple("value");
		doveadm_print("row");
		/* One header, one field: the row is complete and must already be
		   on the wire before deinit (which is what a command's caller sees
		   between the last print and the reply line). */
		test_assert_strcmp_idx(str_c(out), "row\t", i);
		doveadm_print_deinit();
	}

	o_stream_destroy(&doveadm_print_ostream);
	str_free(&out);
	test_end();
}

static void test_doveadm_print_server_multi_column(void)
{
	string_t *out = str_new(default_pool, 128);

	test_begin("doveadm-print-server multi-column rows flush per row");
	doveadm_print_ostream = o_stream_create_buffer(out);

	doveadm_print_init(DOVEADM_PRINT_TYPE_SERVER);
	doveadm_print_header_simple("a");
	doveadm_print_header_simple("b");
	doveadm_print("1");
	test_assert_strcmp(str_c(out), "");
	doveadm_print("2");
	test_assert_strcmp(str_c(out), "1\t2\t");
	doveadm_print_deinit();

	/* Next command has a different column count: must not inherit two. */
	str_truncate(out, 0);
	doveadm_print_init(DOVEADM_PRINT_TYPE_SERVER);
	doveadm_print_header_simple("only");
	doveadm_print("x");
	test_assert_strcmp(str_c(out), "x\t");
	doveadm_print_deinit();

	o_stream_destroy(&doveadm_print_ostream);
	str_free(&out);
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_doveadm_print_server_header_reset,
		test_doveadm_print_server_multi_column,
		NULL
	};
	return test_run(test_functions);
}
