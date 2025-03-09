/* Copyright (c) 2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "write-full.h"
#include "env-util.h"
#include "master-interface.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "test-common.h"

#define DATA(data) (const unsigned char *)data"\xff", sizeof(data"\xff")-2

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
	       "\x00\x00\x00\x00\x00\x00\x00\x01"), // full size
	  "Full size mismatch" },

	/* cache path count is truncated */
	{ DATA("DOVECOT-CONFIG\t1.0\n"
	       "\x00\x00\x00\x00\x00\x00\x00\x04" // full size
	       "\x00\x00\x00"), // cache path count
	  "Full size mismatch" },

	/* event filter count is truncated */
	{ DATA("DOVECOT-CONFIG\t1.0\n"
	       "\x00\x00\x00\x00\x00\x00\x00\x08" // full size
	       "\x00\x00\x00\x00" // cache path count
	       "\x00\x00\x00"), // event filter count
	  "Full size mismatch" },

	/* event filter strings are truncated */
	{ DATA("DOVECOT-CONFIG\t1.0\n"
	       "\x00\x00\x00\x00\x00\x00\x00\x08" // full size
	       "\x00\x00\x00\x00" // cache path count
	       "\x00\x00\x10\x00"), // event filter count
	  "'filter string' points outside area" },

	/* full file size is 7 bytes, which makes the first block size
	   truncated, since it needs 8 bytes */
	{ DATA("DOVECOT-CONFIG\t1.0\n"
	       "\x00\x00\x00\x00\x00\x00\x00\x11" // full size
	       "\x00\x00\x00\x00" // cache path count
	       "\x00\x00\x00\x01" // event filter count
	       "\x00" // event filter[0]
	       "\x00" // override event filter[0]
	       "\x00\x00\x00\x00\x00\x00\x00"), // block size
	  "Area too small when reading size of 'block size'" },
	/* first block size is 0, which is too small */
	{ DATA("DOVECOT-CONFIG\t1.0\n"
	       "\x00\x00\x00\x00\x00\x00\x00\x12" // full size
	       "\x00\x00\x00\x00" // cache path count
	       "\x00\x00\x00\x01" // event filter count
	       "\x00" // event filter[0]
	       "\x00" // override event filter[0]
	       "\x00\x00\x00\x00\x00\x00\x00\x00"), // block size
	  "'block name' points outside area" },
	/* first block size is 1, but full file size is too small */
	{ DATA("DOVECOT-CONFIG\t1.0\n"
	       "\x00\x00\x00\x00\x00\x00\x00\x12" // full size
	       "\x00\x00\x00\x00" // cache path count
	       "\x00\x00\x00\x01" // event filter count
	       "\x00" // event filter[0]
	       "\x00" // override event filter[0]
	       "\x00\x00\x00\x00\x00\x00\x00\x01"), // block size
	  "'block size' points outside are" },
	/* block name is not NUL-terminated */
	{ DATA("DOVECOT-CONFIG\t1.0\n"
	       "\x00\x00\x00\x00\x00\x00\x00\x14" // full size
	       "\x00\x00\x00\x00" // cache path count
	       "\x00\x00\x00\x01" // event filter count
	       "\x00" // event filter[0]
	       "\x00" // override event filter[0]
	       "\x00\x00\x00\x00\x00\x00\x00\x01" // block size
	       "N"
	       "\x00"), // trailing garbage so we can have NUL
	  "Settings block doesn't end with NUL at offset" },

	/* settings count is truncated */
	{ DATA("DOVECOT-CONFIG\t1.0\n"
	       "\x00\x00\x00\x00\x00\x00\x00\x17" // full size
	       "\x00\x00\x00\x00" // cache path count
	       "\x00\x00\x00\x01" // event filter count
	       "\x00" // event filter[0]
	       "\x00" // override event filter[0]
	       "\x00\x00\x00\x00\x00\x00\x00\x05" // block size
	       "N\x00" // block name
	       "\x00\x00\x00"),
	  "Area too small when reading uint of 'settings count'" },

	/* settings keys are truncated */
	{ DATA("DOVECOT-CONFIG\t1.0\n"
	       "\x00\x00\x00\x00\x00\x00\x00\x18" // full size
	       "\x00\x00\x00\x00" // cache path count
	       "\x00\x00\x00\x01" // event filter count
	       "\x00" // event filter[0]
	       "\x00" // override event filter[0]
	       "\x00\x00\x00\x00\x00\x00\x00\x06" // block size
	       "N\x00" // block name
	       "\x00\x00\x01\x00"), // settings count
	  "'setting key' points outside area" },

	/* filter count is truncated */
	{ DATA("DOVECOT-CONFIG\t1.0\n"
	       "\x00\x00\x00\x00\x00\x00\x00\x1D" // full size
	       "\x00\x00\x00\x00" // cache path count
	       "\x00\x00\x00\x01" // event filter count
	       "\x00" // event filter[0]
	       "\x00" // override event filter[0]
	       "\x00\x00\x00\x00\x00\x00\x00\x0B" // block size
	       "N\x00" // block name
	       "\x00\x00\x00\x01" // settings count
	       "K\x00" // setting[0] key
	       "\x00\x00\x00"), // filter count
	  "Area too small when reading uint of 'filter count'" },

	/* filter settings size is truncated */
	{ DATA("DOVECOT-CONFIG\t1.0\n"
	       "\x00\x00\x00\x00\x00\x00\x00\x25" // full size
	       "\x00\x00\x00\x00" // cache path count
	       "\x00\x00\x00\x01" // event filter count
	       "\x00" // event filter[0]
	       "\x00" // override event filter[0]
	       "\x00\x00\x00\x00\x00\x00\x00\x12" // block size
	       "N\x00" // block name
	       "\x00\x00\x00\x01" // settings count
	       "K\x00" // setting[0] key
	       "\x00\x00\x00\x01" // filter count
	       "\x00\x00\x00\x00\x00\x00\x00"), // filter settings size
	  "Area too small when reading size of 'filter settings size'" },

	/* filter settings is truncated */
	{ DATA("DOVECOT-CONFIG\t1.0\n"
	       "\x00\x00\x00\x00\x00\x00\x00\x26" // full size
	       "\x00\x00\x00\x00" // cache path count
	       "\x00\x00\x00\x01" // event filter count
	       "\x00" // event filter[0]
	       "\x00" // override event filter[0]
	       "\x00\x00\x00\x00\x00\x00\x00\x14" // block size
	       "N\x00" // block name
	       "\x00\x00\x00\x01" // settings count
	       "K\x00" // setting[0] key
	       "\x00\x00\x00\x01" // filter count
	       "\x00\x00\x00\x00\x00\x00\x10\x00"), // filter settings size
	  "'filter settings size' points outside area" },
	/* filter error is missing */
	{ DATA("DOVECOT-CONFIG\t1.0\n"
	       "\x00\x00\x00\x00\x00\x00\x00\x33" // full size
	       "\x00\x00\x00\x00" // cache path count
	       "\x00\x00\x00\x01" // event filter count
	       "\x00" // event filter[0]
	       "\x00" // override event filter[0]
	       "\x00\x00\x00\x00\x00\x00\x00\x21" // block size
	       "N\x00" // block name
	       "\x00\x00\x00\x01" // settings count
	       "K\x00" // setting[0] key
	       "\x00\x00\x00\x01" // filter count
	       "\x00\x00\x00\x00\x00\x00\x00\x00" // filter settings size
	       "\x00\x00\x00\x00" // event filter index
	       "\x00\x00\x00\x00\x00\x00\x00\x00" // filter settings offset
	       "\x00"), // safety NUL
	  "'filter error string' points outside area" },
	/* filter error is not NUL-terminated */
	{ DATA("DOVECOT-CONFIG\t1.0\n"
	       "\x00\x00\x00\x00\x00\x00\x00\x41" // full size
	       "\x00\x00\x00\x00" // cache path count
	       "\x00\x00\x00\x01" // event filter count
	       "\x00" // event filter[0]
	       "\x00" // override event filter[0]
	       "\x00\x00\x00\x00\x00\x00\x00\x2F" // block size
	       "master_service\x00" // block name
	       "\x00\x00\x00\x01" // settings count
	       "K\x00" // setting[0] key
	       "\x00\x00\x00\x01" // filter count
	       "\x00\x00\x00\x00\x00\x00\x00\x01" // filter settings size
	       "E" // filter error string
	       "\x00\x00\x00\x00" // event filter index
	       "\x00\x00\x00\x00\x00\x00\x00\x00" // filter settings offset
	       "\x00"), // safety NUL
	  "'filter error string' points outside area" },
	/* include group count is truncated */
	{ DATA("DOVECOT-CONFIG\t1.0\n"
	       "\x00\x00\x00\x00\x00\x00\x00\x44" // full size
	       "\x00\x00\x00\x00" // cache path count
	       "\x00\x00\x00\x01" // event filter count
	       "\x00" // event filter[0]
	       "\x00" // override event filter[0]
	       "\x00\x00\x00\x00\x00\x00\x00\x32" // block size
	       "master_service\x00" // block name
	       "\x00\x00\x00\x01" // settings count
	       "K\x00" // setting[0] key
	       "\x00\x00\x00\x01" // filter count
	       "\x00\x00\x00\x00\x00\x00\x00\x04" // filter settings size
	       "\x00" // filter error string
	       "\x00\x00\x00" // include group count
	       "\x00\x00\x00\x00" // event filter index
	       "\x00\x00\x00\x00\x00\x00\x00\x00" // filter settings offset
	       "\x00"), // safety NUL
	  "Area too small when reading uint of 'include group count'" },
	/* include group count is too large */
	{ DATA("DOVECOT-CONFIG\t1.0\n"
	       "\x00\x00\x00\x00\x00\x00\x00\x45" // full size
	       "\x00\x00\x00\x00" // cache path count
	       "\x00\x00\x00\x01" // event filter count
	       "\x00" // event filter[0]
	       "\x00" // override event filter[0]
	       "\x00\x00\x00\x00\x00\x00\x00\x33" // block size
	       "master_service\x00" // block name
	       "\x00\x00\x00\x01" // settings count
	       "K\x00" // setting[0] key
	       "\x00\x00\x00\x01" // filter count
	       "\x00\x00\x00\x00\x00\x00\x00\x05" // filter settings size
	       "\x00" // filter error string
	       "\x00\x00\x00\x01" // include group count
	       "\x00\x00\x00\x00" // event filter index
	       "\x00\x00\x00\x00\x00\x00\x00\x00" // filter settings offset
	       "\x00"), // safety NUL
	  "'group label string' points outside area" },
	/* group label not NUL-terminated */
	{ DATA("DOVECOT-CONFIG\t1.0\n"
	       "\x00\x00\x00\x00\x00\x00\x00\x46" // full size
	       "\x00\x00\x00\x00" // cache path count
	       "\x00\x00\x00\x01" // event filter count
	       "\x00" // event filter[0]
	       "\x00" // override event filter[0]
	       "\x00\x00\x00\x00\x00\x00\x00\x34" // block size
	       "master_service\x00" // block name
	       "\x00\x00\x00\x01" // settings count
	       "K\x00" // setting[0] key
	       "\x00\x00\x00\x01" // filter count
	       "\x00\x00\x00\x00\x00\x00\x00\x06" // filter settings size
	       "\x00" // filter error string
	       "\x00\x00\x00\x01" // include group count
	       "G" // group label
	       "\x00\x00\x00\x00" // event filter index
	       "\x00\x00\x00\x00\x00\x00\x00\x00" // filter settings offset
	       "\x00"), // safety NUL
	  "'group label string' points outside area" },
	/* group name not NUL-terminated */
	{ DATA("DOVECOT-CONFIG\t1.0\n"
	       "\x00\x00\x00\x00\x00\x00\x00\x48" // full size
	       "\x00\x00\x00\x00" // cache path count
	       "\x00\x00\x00\x01" // event filter count
	       "\x00" // event filter[0]
	       "\x00" // override event filter[0]
	       "\x00\x00\x00\x00\x00\x00\x00\x36" // block size
	       "master_service\x00" // block name
	       "\x00\x00\x00\x01" // settings count
	       "K\x00" // setting[0] key
	       "\x00\x00\x00\x01" // filter count
	       "\x00\x00\x00\x00\x00\x00\x00\x08" // filter settings size
	       "\x00" // filter error string
	       "\x00\x00\x00\x01" // include group count
	       "G\x00" // group label
	       "N" // group name
	       "\x00\x00\x00\x00" // event filter index
	       "\x00\x00\x00\x00\x00\x00\x00\x00" // filter settings offset
	       "\x00"), // safety NUL
	  "'group name string' points outside area" },
	/* invalid filter string */
	{ DATA("DOVECOT-CONFIG\t1.0\n"
	       "\x00\x00\x00\x00\x00\x00\x00\x3A" // full size
	       "\x00\x00\x00\x00" // cache path count
	       "\x00\x00\x00\x01" // event filter count
	       "F\x00" // event filter[0]
	       "F\x00" // override event filter[0]
	       "\x00\x00\x00\x00\x00\x00\x00\x26" // block size
	       "N\x00" // block name
	       "\x00\x00\x00\x01" // settings count
	       "K\x00" // setting[0] key
	       "\x00\x00\x00\x01" // filter count
	       "\x00\x00\x00\x00\x00\x00\x00\x05" // filter settings size
	       "\x00" // filter error string
	       "\x00\x00\x00\x00" // include group count
	       "\x00\x00\x00\x00" // event filter index
	       "\x00\x00\x00\x00\x00\x00\x00\x00" // filter settings offset
	       "\x00"), // safety NUL
	  "Received invalid filter 'F' at index 0: event filter: syntax error" },

	/* Duplicate block name */
	{ DATA("DOVECOT-CONFIG\t1.0\n"
	       "\x00\x00\x00\x00\x00\x00\x00\x42" // full size
	       "\x00\x00\x00\x00" // cache path count
	       "\x00\x00\x00\x01" // event filter count
	       "\x00" // event filter[0]
	       "\x00" // override event filter[0]
	       "\x00\x00\x00\x00\x00\x00\x00\x26" // block size
	       "N\x00" // block name
	       "\x00\x00\x00\x01" // settings count
	       "K\x00" // setting[0] key
	       "\x00\x00\x00\x01" // filter count
	       "\x00\x00\x00\x00\x00\x00\x00\x05" // filter settings size
	       "\x00" // filter error string
	       "\x00\x00\x00\x00" // include group count
	       "\x00\x00\x00\x00" // event filter index
	       "\x00\x00\x00\x00\x00\x00\x00\x00" // filter settings offset
	       "\x00" // safety NUL
	       "\x00\x00\x00\x00\x00\x00\x00\x02" // 2nd block size
	       "N\x00"), // 2nd block name
	  "Duplicate block name 'N'" },
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
