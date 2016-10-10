/* Copyright (c) 2002-2016 Dovecot authors, see the included COPYING file
 */

#include "lib.h"
#include "test-lib.h"
#include "buffer.h"
#include "str.h"
#include "istream.h"
#include "ostream.h"
#include "program-client.h"

static const char *pclient_test_io_string = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.\n"
					    "Praesent vehicula ac leo vel placerat. Nullam placerat \n"
					    "volutpat leo, sed ultricies felis pulvinar quis. Nam \n"
					    "tempus, augue ut tempor cursus, neque felis commodo lacus, \n"
					    "sit amet tincidunt arcu justo vel augue. Proin dapibus \n"
					    "vulputate maximus. Mauris congue lacus felis, sed varius \n"
					    "leo finibus sagittis. Cum sociis natoque penatibus et magnis \n"
					    "dis parturient montes, nascetur ridiculus mus. Aliquam \n"
					    "laoreet arcu a hendrerit consequat. Duis vitae erat tellus.";

static
struct program_client_settings pc_set = {
	.client_connect_timeout_msecs = 5000,
	.input_idle_timeout_secs = 1000,
	.debug = FALSE,
};

static
void test_program_success(void) {
	test_begin("test_program_success");

	const char *const args[] = {
		"hello", "world", NULL
	};

	struct program_client *pc =
		program_client_local_create("/bin/echo", args, &pc_set);

	buffer_t *output = buffer_create_dynamic(default_pool, 16);
	struct ostream *os = test_ostream_create(output);
	program_client_set_output(pc, os);

	test_assert(program_client_run(pc) == 1);
	test_assert(strcmp(str_c(output), "hello world\n") == 0);

	program_client_destroy(&pc);

	o_stream_unref(&os);
	buffer_free(&output);

	test_end();
}

static
void test_program_io_sync(void) {
	test_begin("test_program_io (sync)");

	const char *const args[] = {
		NULL
	};

	struct program_client *pc =
		program_client_local_create("/bin/cat", args, &pc_set);

	struct istream *is = test_istream_create(pclient_test_io_string);
	program_client_set_input(pc, is);

	buffer_t *output = buffer_create_dynamic(default_pool, 16);
	struct ostream *os = test_ostream_create(output);
	program_client_set_output(pc, os);

	test_assert(program_client_run(pc) == 1);
	test_assert(strcmp(str_c(output), pclient_test_io_string) == 0);

	program_client_destroy(&pc);

	i_stream_unref(&is);
	o_stream_unref(&os);
	buffer_free(&output);

	test_end();
}

static
void test_program_io_async_callback(int result, int *ret)
{
	*ret = result;
	test_assert(result == 1);
	io_loop_stop(current_ioloop);
}

static
void test_program_io_async(void) {
	test_begin("test_program_io (async)");

	int ret;
	struct ioloop *ioloop = io_loop_create();
	io_loop_set_current(ioloop);

	const char *const args[] = {
		NULL
	};

	struct program_client *pc =
		program_client_local_create("/bin/cat", args, &pc_set);

	struct istream *is = test_istream_create(pclient_test_io_string);
	program_client_set_input(pc, is);

	buffer_t *output = buffer_create_dynamic(default_pool, 16);
	struct ostream *os = test_ostream_create(output);
	program_client_set_output(pc, os);

	program_client_run_async(pc, test_program_io_async_callback, &ret);

	io_loop_run(ioloop);

	test_assert(strcmp(str_c(output), pclient_test_io_string) == 0);

	program_client_destroy(&pc);

	i_stream_unref(&is);
	o_stream_unref(&os);
	buffer_free(&output);

	io_loop_destroy(&ioloop);

	test_end();
}

static
void test_program_failure(void) {
	test_begin("test_program_failure");

	const char *const args[] = {
		NULL
	};

	struct program_client *pc =
		program_client_local_create("/bin/false", args, &pc_set);

	buffer_t *output = buffer_create_dynamic(default_pool, 16);
	struct ostream *os = test_ostream_create(output);
	program_client_set_output(pc, os);

	test_assert(program_client_run(pc) == 0);
	test_assert(strcmp(str_c(output), "") == 0);

	program_client_destroy(&pc);

	o_stream_unref(&os);
	buffer_free(&output);

	test_end();
}

int main(void)
{
	void (*tests[])(void) = {
		test_program_success,
		test_program_io_sync,
		test_program_io_async,
		test_program_failure,
		NULL
	};

	return test_run(tests);
}
