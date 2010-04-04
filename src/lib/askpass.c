/* Copyright (c) 2006-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "askpass.h"

#include <stdio.h>
#include <termios.h>
#include <fcntl.h>
#include <unistd.h>

void askpass(const char *prompt, char *buf, size_t buf_size)
{
        struct termios old_tio, tio;
	bool restore_tio = FALSE;
	size_t pos;
	char ch;
	int fd;

	if (!isatty(STDIN_FILENO))
		i_fatal("stdin isn't a TTY");

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

	/* read the password */
	pos = 0;
	while (read(fd, &ch, 1) > 0) {
		if (pos >= buf_size-1)
			break;
		if (ch == '\n' || ch == '\r')
			break;
		buf[pos++] = ch;
	}
	buf[pos] = '\0';

	if (restore_tio)
		(void)tcsetattr(fd, TCSAFLUSH, &old_tio);

	fputs("\n", stderr); fflush(stderr);
	(void)close(fd);
}

const char *t_askpass(const char *prompt)
{
	char buf[1024];

	askpass(prompt, buf, sizeof(buf));
	return t_strdup(buf);
}
