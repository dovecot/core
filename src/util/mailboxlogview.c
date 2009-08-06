/* Copyright (c) 2007-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "hex-binary.h"
#include "mailbox-log.h"

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>

static const char *unixdate2str(time_t timestamp)
{
	static char buf[64];
	struct tm *tm;

	tm = localtime(&timestamp);
	strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm);
	return buf;
}

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
		i_fatal("rec read() %"PRIuSIZE_T" != %"PRIuSIZE_T,
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
	}
	printf(" %s", binary_to_hex(rec.mailbox_guid,
				    sizeof(rec.mailbox_guid)));

	timestamp = ((uint32_t)rec.timestamp[0] << 24) |
		((uint32_t)rec.timestamp[1] << 16) |
		((uint32_t)rec.timestamp[2] << 8) |
		(uint32_t)rec.timestamp[3];
	printf(" (%s)\n", unixdate2str(timestamp));
	return 1;
}

int main(int argc, const char *argv[])
{
	int fd, ret;

	lib_init();

	if (argc < 2)
		i_fatal("Usage: logview dovecot.mailbox.log");

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		i_error("open(): %m");
		return 1;
	}

	do {
		T_BEGIN {
			ret = dump_record(fd);
		} T_END;
	} while (ret > 0);
	return 0;
}
