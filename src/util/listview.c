/* Copyright (c) 2007-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "crc32.h"
#include "mail-index.h"
#include "mailbox-list-index-private.h"

#include <stdio.h>
#include <stdlib.h>

static struct mailbox_list_index_header hdr;

static uint32_t mail_index_offset_to_uint32(uint32_t offset)
{
	const unsigned char *buf = (const unsigned char *) &offset;

	if ((offset & 0x80808080) != 0x80808080)
		return 0;

	return (((uint32_t)buf[3] & 0x7f) << 2) |
		(((uint32_t)buf[2] & 0x7f) << 9) |
		(((uint32_t)buf[1] & 0x7f) << 16) |
		(((uint32_t)buf[0] & 0x7f) << 23);
}

static void dump_hdr(int fd)
{
	int ret;

	ret = read(fd, &hdr, sizeof(hdr));
	if (ret != sizeof(hdr)) {
		i_fatal("file hdr read() %d != %"PRIuSIZE_T"\n",
			ret, sizeof(hdr));
	}

	printf("version = %u.%u\n", hdr.major_version, hdr.minor_version);
	printf("header size = %u\n", hdr.header_size);
	printf("uid validity = %u\n", hdr.uid_validity);
	printf("file seq = %u\n", hdr.file_seq);
	printf("next uid = %u\n", hdr.next_uid);
	printf("used space = %u\n", hdr.used_space);
	printf("deleted space = %u\n", hdr.deleted_space);
}

static void dump_dir(int fd, unsigned int show_offset, const char *path)
{
	struct mailbox_list_dir_record dir;
	struct mailbox_list_record rec;
	off_t offset;
	char name[1024];
	unsigned int i;
	int ret;

	offset = lseek(fd, 0, SEEK_CUR);
	ret = read(fd, &dir, sizeof(dir));
	if (ret == 0) {
		if (*path != '\0')
			i_fatal("unexpected EOF when reading dir");
		return;
	}

	if (ret != sizeof(dir))
		i_fatal("dir read() %d != %"PRIuSIZE_T, ret, sizeof(dir));

	dir.next_offset = mail_index_offset_to_uint32(dir.next_offset);
	printf("%s: DIR: offset=%"PRIuUOFF_T" next_offset=%u count=%u dir_size=%u\n",
	       path, offset, dir.next_offset, dir.count, dir.dir_size);

	if (dir.next_offset != 0 && dir.next_offset != show_offset) {
		lseek(fd, dir.next_offset, SEEK_SET);
		dump_dir(fd, show_offset, path);
		return;
	}

	offset += sizeof(dir);
	for (i = 0; i < dir.count; i++) {
		lseek(fd, offset, SEEK_SET);
		ret = read(fd, &rec, sizeof(rec));
		if (ret == 0)
			i_fatal("unexpected EOF, %d/%d records", i, dir.count);

		if (ret != sizeof(rec)) {
			i_fatal("rec read() %d != %"PRIuSIZE_T,
				ret, sizeof(rec));
		}
		rec.dir_offset = mail_index_offset_to_uint32(rec.dir_offset);

		ret = pread(fd, name, sizeof(name)-1, rec.name_offset);
		name[ret < 0 ? 0 : ret] = '\0';

		printf("%s%s: offset=%"PRIuUOFF_T" uid=%u "
		       "name_offset=%u name_hash=%u", path, name, offset,
		       rec.uid, rec.name_offset, rec.name_hash);

		if (rec.deleted != 0)
			printf(" deleted=%u", rec.deleted);
		if (rec.dir_offset != 0)
			printf(" dir_offset=%u", rec.dir_offset);
		printf("\n");

		if (ret <= 0)
			printf("%s%s: - invalid name_offset", path, name);
		else if (strlen(name) == (size_t)ret) {
			printf("%s%s: - name missing NUL terminator",
			       path, name);
		}

		if (crc32_str(name) != rec.name_hash) {
			printf("%s%s: - invalid name hash %u vs %u\n",
			       path, name, crc32_str(name), rec.name_hash);
		}

		if (rec.dir_offset != 0) T_BEGIN {
			const char *new_path;

			lseek(fd, rec.dir_offset, SEEK_SET);
			if (*path == '\0')
				new_path = t_strdup_printf("%s/", name);
			else
				new_path = t_strdup_printf("%s%s/", path, name);
			dump_dir(fd, show_offset, new_path);
		} T_END;

		offset += sizeof(rec);
	}
}

int main(int argc ATTR_UNUSED, const char *argv[])
{
	int fd;

	lib_init();

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		i_error("open(): %m");
		return 1;
	}

	printf("-- LIST INDEX: %s\n", argv[1]);

	dump_hdr(fd);
	lseek(fd, hdr.header_size, SEEK_SET);

	printf("---------------\n");

	dump_dir(fd, argv[2] == NULL ? 0 : atoi(argv[2]), "");
	return 0;
}
