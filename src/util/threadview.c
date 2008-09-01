/* Copyright (c) 2007-2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mmap-util.h"
#include "mail-index-private.h"
#include "mail-index-strmap.h"

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

static uint32_t max_likely_index;

uint32_t mail_index_offset_to_uint32(uint32_t offset)
{
	const unsigned char *buf = (const unsigned char *) &offset;

	if ((offset & 0x80808080) != 0x80808080)
		return 0;

	return (((uint32_t)buf[3] & 0x7f) << 2) |
		(((uint32_t)buf[2] & 0x7f) << 9) |
		(((uint32_t)buf[1] & 0x7f) << 16) |
		(((uint32_t)buf[0] & 0x7f) << 23);
}

int mail_index_unpack_num(const uint8_t **p, const uint8_t *end,
			  uint32_t *num_r)
{
	const uint8_t *c = *p;
	uint32_t value = 0;
	unsigned int bits = 0;

	for (;;) {
		if (unlikely(c == end)) {
			/* we should never see EOF */
			*num_r = 0;
			return -1;
		}

		value |= (*c & 0x7f) << bits;
		if (*c < 0x80)
			break;

		bits += 7;
		c++;
	}

	if (unlikely(bits >= 32)) {
		/* broken input */
		*p = end;
		*num_r = 0;
		return -1;
	}

	*p = c + 1;
	*num_r = value;
	return 0;
}

static size_t dump_hdr(const struct mail_index_strmap_header *hdr)
{
	printf("version = %u\n", hdr->version);
	printf("uid validity = %u\n", hdr->uid_validity);
	return sizeof(*hdr);
}

static int dump_record(const uint8_t **p, const uint8_t *end, uint32_t *uid)
{
	uint32_t uid_diff, n, i, count, crc32, idx;
	size_t size;

	/* <uid diff> <n> <crc32>*count <str_idx>*count */
	if (mail_index_unpack_num(p, end, &uid_diff) <  0)
		return -1;
	*uid += uid_diff;

	if (mail_index_unpack_num(p, end, &n) <  0)
		return -1;
	printf(" - uid %u: n=%u\n", *uid, n);

	count = n < 2 ? n + 1 : n;
	size = sizeof(crc32)*count + sizeof(idx)*count;
	if (*p + size > end)
		return -1;
	for (i = 0; i < count; i++) {
		if (i == 0)
			printf("   - message-id: ");
		else if (i == 1) {
			if (n == 1)
				printf("   - in-reply-to: ");
			else
				printf("   - references[1]: ");
		} else {
			printf("   - references[%u]: ", i);
		}
		memcpy(&crc32, *p + sizeof(crc32)*i, sizeof(crc32));
		memcpy(&idx, *p + sizeof(crc32)*count + sizeof(idx)*i, sizeof(idx));
		printf("crc32=%08x index=%u\n", crc32, idx);
		if (idx > max_likely_index)
			printf(" - index probably broken\n");
	}
	*p += size;
	return 0;
}

static int dump_block(const uint8_t *data, const uint8_t *end, uint32_t *uid)
{
	const uint8_t *p;
	uint32_t block_size;

	if (data + 4 >= end)
		return -1;

	memcpy(&block_size, data, sizeof(block_size));
	block_size = mail_index_offset_to_uint32(block_size) >> 2;
	printf(" - block_size=%u\n", block_size);
	if (block_size == 0) {
		/* finished */
		return -1;
	}
	if (data + sizeof(block_size) + block_size > end) {
		printf("   - broken!\n");
		return -1;
	}
	p = data + sizeof(block_size);
	end = p + block_size;

	*uid += 1;
	while (p != end) {
		if (dump_record(&p, end, uid) < 0) {
			printf(" - broken\n");
			return -1;
		}
	}
	return p - data;
}

int main(int argc, const char *argv[])
{
	unsigned int pos;
	const void *map, *end;
	struct stat st;
	uint32_t uid;
	int fd, ret;

	lib_init();

	if (argc < 2)
		i_fatal("Usage: threadview dovecot.index.thread");

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		i_error("open(%s) failed: %m", argv[1]);
		return 1;
	}

	if (fstat(fd, &st) < 0) {
		i_error("fstat(%s) failed: %m", argv[1]);
		return 1;
	}
	max_likely_index = (st.st_size / 8) * 2;

	map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	end = CONST_PTR_OFFSET(map, st.st_size);
	pos = dump_hdr(map);
	uid = 0;
	do {
		printf("block at offset %u:\n", pos);
		T_BEGIN {
			ret = dump_block(CONST_PTR_OFFSET(map, pos), end, &uid);
			pos += ret;
		} T_END;
	} while (ret > 0);
	return 0;
}
