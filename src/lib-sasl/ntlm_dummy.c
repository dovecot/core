/* Copyright (c) 2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "base64.h"
#include "istream.h"

#include <stdio.h>

/* Dummy NTLM helper

   This has nothing to do with actual NTLM; it just serves as a means to test
   the winbind server mechanisms.
 */

#define USER "user"
#define MAX_LINE_LENGTH 16384

static void run_ntlm_cmd_yr(void)
{
	static const char *challenge = "Challenge";
	const size_t chal_size = strlen(challenge);
	string_t *str;

	str = t_str_new(MAX_BASE64_ENCODED_SIZE(chal_size + 1));
	base64_encode(challenge, chal_size, str);

	printf("TT %s\n", str_c(str));
}

static void run_ntlm_cmd_kk(const char *param)
{
	static const char *response = "Response: ";
	static const char *user = USER;
	const size_t resp_size = strlen(response);
	const size_t user_size = strlen(user);
	const unsigned char *data;
	size_t size;
	buffer_t *buf;

	buf = t_base64_decode_str(param);
	data = buf->data;
	size = buf->used;

	if (size <= resp_size ||
	    memcmp(data, response, resp_size) != 0) {
		printf("BH Invalid client response\n");
		return;
	}
	data += resp_size;
	size -= resp_size;

	if (size <= user_size || memcmp(data, user, user_size) != 0 ||
	    data[user_size] != '@') {
		printf("NA No such user\n");
		return;
	}

	printf("AF user@EXAMPLE.COM\n");
}

static void run_ntlm(void)
{
	struct istream *input;
	const char *line;
	int fd = 0;

	input = i_stream_create_fd_autoclose(&fd, MAX_LINE_LENGTH);

	while ((line = i_stream_read_next_line(input)) != NULL) {
		const char *const *args = t_strsplit_spaces(line, " ");

		if (strcmp(args[0], "YR") == 0) {
			if (args[1] != NULL && strlen(args[1]) > 0)
				i_fatal("Invalid YR command: %s", line);
			run_ntlm_cmd_yr();
		} else if (strcmp(args[0], "KK") == 0) {
			if (args[1] == NULL || args[2] != NULL)
				i_fatal("Invalid KK command: %s", line);
			run_ntlm_cmd_kk(args[1]);
		} else {
			i_fatal("Invalid command: %s", line);
		}
		fflush(stdout);
	}

	i_stream_destroy(&input);
}

int main(int argc, char *argv[])
{
	lib_init();

	if (argc < 2)
		i_fatal("Invalid arguments");
	if (strcmp(argv[1], "--helper-protocol=squid-2.5-ntlmssp") == 0)
		run_ntlm();
	else
		i_fatal("Invalid arguments");

	lib_deinit();
}
