/* Copyright (c) 2006-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "str.h"
#include "askpass.h"

#include <stdio.h>
#include <termios.h>
#include <fcntl.h>
#include <unistd.h>

static void askpass_str(const char *prompt, buffer_t *pass)
{
        struct termios old_tio, tio;
	bool tty, restore_tio = FALSE;
	char ch;
	int fd;

	tty = isatty(STDIN_FILENO);
	if (tty) {
		fputs(prompt, stderr);
		fflush(stderr);

		fd = open("/dev/tty", O_RDONLY);
		if (fd < 0)
			i_fatal("open(/dev/tty) failed: %m");

		/* turn off echo */
		if (tcgetattr(fd, &old_tio) == 0) {
			restore_tio = TRUE;
			tio = old_tio;
			tio.c_lflag &= ~(ECHO | ECHONL);
			(void)tcsetattr(fd, TCSAFLUSH, &tio);
		}
	} else {
		/* read it from stdin without showing a prompt */
		fd = STDIN_FILENO;
	}

	/* read the password */
	while (read(fd, &ch, 1) > 0) {
		if (ch == '\n' || ch == '\r')
			break;
		buffer_append_c(pass, ch);
	}

	if (tty) {
		if (restore_tio)
			(void)tcsetattr(fd, TCSAFLUSH, &old_tio);

		fputs("\n", stderr); fflush(stderr);
		(void)close(fd);
	}
}

void askpass(const char *prompt, char *buf, size_t buf_size)
{
	buffer_t str;

	buffer_create_data(&str, buf, buf_size);
	askpass_str(prompt, &str);
	buffer_append_c(&str, '\0');
}

const char *t_askpass(const char *prompt)
{
	string_t *str = t_str_new(32);

	askpass_str(prompt, str);
	return str_c(str);
}
