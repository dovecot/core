/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "write-full.h"
#include "env-util.h"
#include "master-interface.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "test-common.h"

#define DATA(data) (const unsigned char *)data"\xff", sizeof(data"\xff")-2

/* we only need to use 1 byte */
#ifdef WORDS_BIGENDIAN
#  define NUM64(n) "\x00\x00\x00\x00\x00\x00\x00"n
#  define NUM32(n) "\x00\x00\x00"n
#else
#  define NUM64(n) n"\x00\x00\x00\x00\x00\x00\x00"
#  define NUM32(n) n"\x00\x00\x00"
#endif

static const struct {
	const unsigned char *data;
	size_t size;
	const char *error;
} tests[] = {
	{ DATA("D"),
	  "File header doesn't begin with DOVECOT-CONFIG line" },
	{ DATA("DOVECOT-CONFIG\t"),
	  "File header doesn't begin with DOVECOT-CONFIG line" },
	{ DATA("DOVECOT-CONFIG\t1.0"),
	  "File header doesn't begin with DOVECOT-CONFIG line" },
	{ DATA("DOVECOT-CONFIG\t2.3\n"),
	  "Unsupported config file version '2.3'" },

	/* full file size = 1, but file is still truncated */
	{ DATA("DOVECOT-CONFIG\t1.0\n" // 19 bytes
	       NUM64("\x01")), // full size
	  "Full size mismatch" },

	/* cache path count is truncated */
	{ DATA("DOVECOT-CONFIG\t1.0\n"
	       NUM64("\x03") // full size
	       "\x00\x00\x00"), // cache path count
	  "Area too small when reading uint of 'config paths count'" },

	/* all keys size is truncated */
	{ DATA("DOVECOT-CONFIG\t1.0\n"
	       NUM64("\x07") // full size
	       NUM32("\x00") // cache path count
	       "\x00\x00\x00"), // all keys size
	  "Area too small when reading uint of 'all keys size'" },

	/* all keys hash key prefix is truncated */
	{ DATA("DOVECOT-CONFIG\t1.0\n"
	       NUM64("\x0C") // full size
	       NUM32("\x00") // cache path count
	       NUM32("\x04") // all keys size
	       "\x00" // 32bit padding
	       "\x00\x00\x00"), // all keys hash key prefix
	  "Area too small when reading uint of 'all keys hash key prefix'" },

	  /* event all keys hash nodes count is truncated */
	{ DATA("DOVECOT-CONFIG\t1.0\n"
	       NUM64("\x10") // full size
	       NUM32("\x00") // cache path count
	       NUM32("\x08") // all keys size
	       "\x00" // 32bit padding
	       NUM32("\x00") // all keys hash key prefix
	       "\x00\x00\x00"), // all keys hash nodes count
	  "Area too small when reading uint of 'all keys hash nodes count'" },
};

static int test_input_to_fd(const unsigned char *data, size_t size)
{
	int fd = test_create_temp_fd();
	if (write_full(fd, data, size) < 0)
		i_fatal("write(temp file) failed: %m");
	if (lseek(fd, 0, SEEK_SET) < 0)
		i_fatal("lseek(temp file) failed: %m");
	return fd;
}

static void test_master_service_settings_read_binary_corruption(void)
{
	const char *error;

	test_begin("master_service_settings_read() - binary corruption");
	for (unsigned int i = 0; i < N_ELEMENTS(tests); i++) {
		struct master_service_settings_input input = {
			.config_fd = test_input_to_fd(tests[i].data, tests[i].size),
			.no_key_validation = TRUE,
		};
		struct master_service_settings_output output;

		test_assert_idx(master_service_settings_read(master_service,
			&input, &output, &error) == -1, i);
		test_assert_idx(strstr(error, tests[i].error) != NULL, i);
		if (strstr(error, tests[i].error) == NULL)
			i_error("%s", error);
	}
	test_end();
}

int main(int argc, char *argv[])
{
	static void (*const test_functions[])(void) = {
		test_master_service_settings_read_binary_corruption,
		NULL
	};
	const enum master_service_flags service_flags =
		MASTER_SERVICE_FLAG_STANDALONE |
		MASTER_SERVICE_FLAG_DONT_SEND_STATS |
		MASTER_SERVICE_FLAG_NO_SSL_INIT;
	master_service = master_service_init("test-master-service-settings",
					     service_flags, &argc, &argv, "");
	int ret = test_run(test_functions);
	master_service_deinit(&master_service);
	return ret;
}
