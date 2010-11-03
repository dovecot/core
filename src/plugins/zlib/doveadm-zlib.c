/* Copyright (c) 2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "istream-zlib.h"
#include "module-dir.h"
#include "doveadm-dump.h"

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

const char *doveadm_zlib_plugin_version = DOVECOT_VERSION;

void doveadm_zlib_plugin_init(struct module *module);
void doveadm_zlib_plugin_deinit(void);

static void cmd_dump_imapzlib(int argc ATTR_UNUSED, char *argv[])
{
	struct istream *input, *input2;
	const unsigned char *data;
	size_t size;
	const char *line;
	int fd;

	fd = open(argv[1], O_RDONLY);
	if (fd < 0)
		i_fatal("open(%s) failed: %m", argv[1]);
	input = i_stream_create_fd(fd, 1024*32, TRUE);
	while ((line = i_stream_read_next_line(input)) != NULL) {
		/* skip tag */
		printf("%s\r\n", line);
		while (*line != ' ' && *line != '\0') line++;
		if (*line == '\0')
			continue;
		line++;

		if (strcmp(line, "OK Begin compression.") == 0 ||
		    strcasecmp(line, "COMPRESS DEFLATE") == 0)
			break;
	}

	input2 = i_stream_create_deflate(input, TRUE);
	i_stream_unref(&input);

	while (i_stream_read_data(input2, &data, &size, 0) != -1) {
		fwrite(data, 1, size, stdout);
		i_stream_skip(input2, size);
	}
	i_stream_unref(&input2);
	fflush(stdout);
}

static bool test_dump_imapzlib(const char *path)
{
	const char *p;
	char buf[4096];
	int fd, ret;
	bool match = FALSE;

	p = strrchr(path, '.');
	if (p == NULL || (strcmp(p, ".in") != 0 && strcmp(p, ".out") != 0))
		return FALSE;

	fd = open(path, O_RDONLY);
	if (fd == -1)
		return FALSE;

	ret = read(fd, buf, sizeof(buf)-1);
	if (ret > 0) {
		buf[ret] = '\0';
		str_lcase(buf);
		match = strstr(buf, " ok begin compression.") != NULL ||
			strstr(buf, " compress deflate") != NULL;
	}
	(void)close(fd);
	return match;
}

struct doveadm_cmd_dump doveadm_cmd_dump_zlib = {
	"imapzlib",
	test_dump_imapzlib,
	cmd_dump_imapzlib
};

void doveadm_zlib_plugin_init(struct module *module ATTR_UNUSED)
{
	doveadm_dump_register(&doveadm_cmd_dump_zlib);
}

void doveadm_zlib_plugin_deinit(void)
{
}
