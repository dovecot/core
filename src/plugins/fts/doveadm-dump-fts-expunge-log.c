/* Copyright (c) 2011-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "hex-binary.h"
#include "guid.h"
#include "doveadm-dump.h"
#include "doveadm-fts.h"

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

struct fts_expunge_log_record {
	uint32_t checksum;
	uint32_t record_size;
	guid_128_t guid;
};

static int dump_record(int fd, buffer_t *buf)
{
	struct fts_expunge_log_record rec;
	off_t offset;
	void *data;
	const uint32_t *expunges, *uids;
	ssize_t ret;
	size_t data_size;
	unsigned int i, uids_count;

	offset = lseek(fd, 0, SEEK_CUR);

	ret = read(fd, &rec, sizeof(rec));
	if (ret == 0)
		return 0;

	if (ret != sizeof(rec))
		i_fatal("rec read() %d != %d", (int)ret, (int)sizeof(rec));

	data_size = rec.record_size - sizeof(rec);
	buffer_set_used_size(buf, 0);
	data = buffer_append_space_unsafe(buf, data_size);
	ret = read(fd, data, data_size);
	if (ret != (ssize_t)data_size)
		i_fatal("rec read() %d != %d", (int)ret, (int)data_size);

	printf("#%"PRIuUOFF_T":\n", offset);
	printf("  checksum  = %8x\n", rec.checksum);
	printf("  size .... = %u\n", rec.record_size);
	printf("  mailbox . = %s\n", guid_128_to_string(rec.guid));

	expunges = CONST_PTR_OFFSET(data, data_size - sizeof(uint32_t));
	printf("  expunges  = %u\n", *expunges);

	printf("  uids .... = ");

	uids = data;
	uids_count = (rec.record_size - sizeof(rec) - sizeof(uint32_t)) /
		sizeof(uint32_t);
	for (i = 0; i < uids_count; i += 2) {
		if (i != 0)
			printf(",");
		if (uids[i] == uids[i+1])
			printf("%u", uids[i]);
		else
			printf("%u-%u", uids[i], uids[i+1]);
	}
	printf("\n");
	return 1;
}

static void cmd_dump_fts_expunge_log(int argc ATTR_UNUSED, char *argv[])
{
	buffer_t *buf;
	int fd, ret;

	fd = open(argv[1], O_RDONLY);
	if (fd < 0)
		i_fatal("open(%s) failed: %m", argv[1]);

	buf = buffer_create_dynamic(default_pool, 1024);
	do {
		T_BEGIN {
			ret = dump_record(fd, buf);
		} T_END;
	} while (ret > 0);
	buffer_free(&buf);
	i_close_fd(&fd);
}

static bool test_dump_fts_expunge_log(const char *path)
{
	const char *p;

	p = strrchr(path, '/');
	if (p++ == NULL)
		p = path;
	return strcmp(p, "dovecot-expunges.log") == 0;
}

struct doveadm_cmd_dump doveadm_cmd_dump_fts_expunge_log = {
	"fts-expunge-log",
	test_dump_fts_expunge_log,
	cmd_dump_fts_expunge_log
};

void doveadm_dump_fts_expunge_log_init(void)
{
	doveadm_dump_register(&doveadm_cmd_dump_fts_expunge_log);
}
