/* Copyright (c) 2007-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "hex-binary.h"
#include "mailbox-log.h"
#include "doveadm-dump.h"

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>

static int dump_record(int fd)
{
	off_t offset;
	ssize_t ret;
	struct mailbox_log_record rec;
	time_t timestamp;

	offset = lseek(fd, 0, SEEK_CUR);

	ret = read(fd, &rec, sizeof(rec));
	if (ret == 0)
		return 0;

	if (ret != sizeof(rec)) {
		i_fatal("rec read() %zu != %zu",
			ret, sizeof(rec));
	}

	printf("#%"PRIuUOFF_T": ", offset);
	switch (rec.type) {
	case MAILBOX_LOG_RECORD_DELETE_MAILBOX:
		printf("delete-mailbox");
		break;
	case MAILBOX_LOG_RECORD_DELETE_DIR:
		printf("delete-dir");
		break;
	case MAILBOX_LOG_RECORD_RENAME:
		printf("rename");
		break;
	case MAILBOX_LOG_RECORD_SUBSCRIBE:
		printf("subscribe");
		break;
	case MAILBOX_LOG_RECORD_UNSUBSCRIBE:
		printf("unsubscribe");
		break;
	case MAILBOX_LOG_RECORD_CREATE_DIR:
		printf("create-dir");
		break;
	}
	printf(" %s", binary_to_hex(rec.mailbox_guid,
				    sizeof(rec.mailbox_guid)));

	timestamp = be32_to_cpu_unaligned(rec.timestamp);
	printf(" (%s)\n", unixdate2str(timestamp));
	return 1;
}

static void cmd_dump_mailboxlog(int argc ATTR_UNUSED, char *argv[])
{
	int fd, ret;

	fd = open(argv[1], O_RDONLY);
	if (fd < 0)
		i_fatal("open(%s) failed: %m", argv[1]);

	do {
		T_BEGIN {
			ret = dump_record(fd);
		} T_END;
	} while (ret > 0);
	i_close_fd(&fd);
}

static bool test_dump_mailboxlog(const char *path)
{
	const char *p;
	int fd;
	struct mailbox_log_record rec;
	bool ret = FALSE;

	p = strrchr(path, '.');
	if (p == NULL || strcmp(p, ".log") != 0)
		return FALSE;

	fd = open(path, O_RDONLY);
	if (fd == -1)
		return FALSE;

	if (read(fd, &rec, sizeof(rec)) == sizeof(rec) &&
	    rec.padding[0] == 0 && rec.padding[1] == 0 && rec.padding[2] == 0) {
		enum mailbox_log_record_type type = rec.type;
		switch (type) {
		case MAILBOX_LOG_RECORD_DELETE_MAILBOX:
		case MAILBOX_LOG_RECORD_DELETE_DIR:
		case MAILBOX_LOG_RECORD_RENAME:
		case MAILBOX_LOG_RECORD_SUBSCRIBE:
		case MAILBOX_LOG_RECORD_UNSUBSCRIBE:
		case MAILBOX_LOG_RECORD_CREATE_DIR:
			ret = TRUE;
			break;
		}
	}
	i_close_fd(&fd);
	return ret;
}

struct doveadm_cmd_dump doveadm_cmd_dump_mailboxlog = {
	"mailboxlog",
	test_dump_mailboxlog,
	cmd_dump_mailboxlog
};
