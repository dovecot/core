/* Copyright (C) 2007 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "hex-binary.h"
#include "mail-index-private.h"
#include "mail-cache-private.h"
#include "mail-transaction-log.h"

#include <stdio.h>
#include <stdlib.h>

static struct mail_index_header hdr;
static ARRAY_DEFINE(extensions, struct mail_index_ext);
static struct mail_cache_header cache_hdr;
static ARRAY_DEFINE(cache_fields, struct mail_cache_field);
static unsigned int cache_ext = (unsigned int)-1;
static unsigned int cache_search_offset = 0;
static int cache_fd = -1;

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

static size_t get_align(size_t name_len)
{
	size_t size = sizeof(struct mail_index_ext_header) + name_len;
	return MAIL_INDEX_HEADER_SIZE_ALIGN(size) - size;
}

static void dump_hdr(int fd)
{
	const struct mail_index_ext_header *ext_hdr;
	struct mail_index_ext ext;
	char *base;
	ssize_t ret;
	unsigned int i, offset, name_offset;

	ret = read(fd, &hdr, sizeof(hdr));
	if (ret != sizeof(hdr)) {
		i_fatal("file hdr read() %"PRIuSIZE_T" != %"PRIuSIZE_T,
			ret, sizeof(hdr));
	}

	printf("version = %u.%u\n", hdr.major_version, hdr.minor_version);
	printf("base header size = %u\n", hdr.base_header_size);
	printf("header size = %u\n", hdr.header_size);
	printf("record size = %u\n", hdr.record_size);
	printf("compat flags = %u\n", hdr.compat_flags);
	printf("index id = %u\n", hdr.indexid);
	printf("flags = %u\n", hdr.flags);
	printf("uid validity = %u\n", hdr.uid_validity);
	printf("next uid = %u\n", hdr.next_uid);
	printf("messages count = %u\n", hdr.messages_count);
	printf("seen messages count = %u\n", hdr.seen_messages_count);
	printf("deleted messages count = %u\n", hdr.deleted_messages_count);
	printf("first recent uid = %u\n", hdr.first_recent_uid);
	printf("first unseen uid lowwater = %u\n", hdr.first_unseen_uid_lowwater);
	printf("first deleted uid lowwater = %u\n", hdr.first_deleted_uid_lowwater);
	printf("log file seq = %u\n", hdr.log_file_seq);
	if (hdr.minor_version == 0) {
		printf("log file int offset = %u\n", hdr.log_file_tail_offset);
		printf("log file ext offset = %u\n", hdr.log_file_head_offset);
	} else {
		printf("log file tail offset = %u\n", hdr.log_file_tail_offset);
		printf("log file head offset = %u\n", hdr.log_file_head_offset);
	}
	printf("sync size = %llu\n", (unsigned long long)hdr.sync_size);
	printf("sync stamp = %u\n", hdr.sync_stamp);
	printf("day stamp = %u\n", hdr.day_stamp);
	for (i = 0; i < 8; i++)
		printf("day first uid[%u] = %u\n", i, hdr.day_first_uid[i]);

	i_array_init(&extensions, 16);
	offset = MAIL_INDEX_HEADER_SIZE_ALIGN(hdr.base_header_size);
	if (offset >= hdr.header_size) {
		printf("no extensions\n");
		return;
	}

	base = i_malloc(hdr.header_size);
	ret = pread(fd, base, hdr.header_size, 0);
	if (ret != (ssize_t)hdr.header_size) {
		i_fatal("file hdr read() %"PRIuSIZE_T" != %u",
			ret, hdr.header_size);
	}

	memset(&ext, 0, sizeof(ext)); i = 0;
	while (offset < hdr.header_size) {
		ext_hdr = CONST_PTR_OFFSET(base, offset);

		offset += sizeof(*ext_hdr);
		name_offset = offset;
		offset += ext_hdr->name_size + get_align(ext_hdr->name_size);

		ext.name = i_strndup(CONST_PTR_OFFSET(base, name_offset),
				     ext_hdr->name_size);
		ext.record_offset = ext_hdr->record_offset;
		ext.record_size = ext_hdr->record_size;
		ext.record_align = ext_hdr->record_align;

		if (strcmp(ext.name, "cache") == 0)
                        cache_ext = i;

		printf("-- Extension %u --\n", i);
		printf("name: %s\n", ext.name);
		printf("hdr_size: %u\n", ext_hdr->hdr_size);
		printf("reset_id: %u\n", ext_hdr->reset_id);
		printf("record_offset: %u\n", ext_hdr->record_offset);
		printf("record_size: %u\n", ext_hdr->record_size);
		printf("record_align: %u\n", ext_hdr->record_align);
		printf("name_size: %u\n", ext_hdr->name_size);

		offset += MAIL_INDEX_HEADER_SIZE_ALIGN(ext_hdr->hdr_size);
		array_append(&extensions, &ext, 1);
		i++;
	}
}

static void dump_cache_hdr(int fd)
{
        struct mail_cache_header_fields fields;
	struct mail_cache_field field;
	uint32_t field_offset, next_offset;
	char *buf;
	ssize_t ret;
	const uint32_t *last_used, *size;
	const uint8_t *type, *decision;
	const char *names;
	unsigned int i;

	ret = read(fd, &cache_hdr, sizeof(cache_hdr));
	if (ret != sizeof(cache_hdr)) {
		i_fatal("cache file hdr read() %"PRIuSIZE_T" != %"PRIuSIZE_T,
			ret, sizeof(cache_hdr));
	}

	field_offset =
		mail_index_offset_to_uint32(cache_hdr.field_header_offset);

	printf("Cache header:\n");
	printf("version: %u\n", cache_hdr.version);
	printf("indexid: %u\n", cache_hdr.indexid);
	printf("file_seq: %u\n", cache_hdr.file_seq);
	printf("continued_record_count: %u\n", cache_hdr.continued_record_count);
	printf("hole_offset: %u\n", cache_hdr.hole_offset);
	printf("used_file_size: %u\n", cache_hdr.used_file_size);
	printf("deleted_space: %u\n", cache_hdr.deleted_space);
	printf("field_header_offset: %u / %u\n",
	       cache_hdr.field_header_offset, field_offset);

	for (;;) {
		ret = pread(fd, &fields, sizeof(fields), field_offset);
		if (ret != sizeof(fields)) {
			i_fatal("cache file fields read() %"
				PRIuSIZE_T" != %"PRIuSIZE_T,
				ret, sizeof(fields));
		}

		next_offset =
			mail_index_offset_to_uint32(fields.next_offset);
		if (next_offset == 0)
			break;

		field_offset = next_offset;
	}

	printf("-- Cache fields: --\n");
	printf("actual used header offset: %u\n", field_offset);

	buf = i_malloc(fields.size);
	ret = pread(fd, buf, fields.size, field_offset);
	if (ret != (ssize_t)fields.size) {
		i_fatal("cache file fields read() %"PRIuSIZE_T" != %u",
			ret, fields.size);
	}
	printf("fields_count: %u\n", fields.fields_count);

	if (fields.fields_count > 10000)
		i_fatal("Broken fields_count");

	last_used = CONST_PTR_OFFSET(buf, MAIL_CACHE_FIELD_LAST_USED());
	size = CONST_PTR_OFFSET(buf, MAIL_CACHE_FIELD_SIZE(fields.fields_count));
	type = CONST_PTR_OFFSET(buf, MAIL_CACHE_FIELD_TYPE(fields.fields_count));
	decision = CONST_PTR_OFFSET(buf, MAIL_CACHE_FIELD_DECISION(fields.fields_count));
	names = CONST_PTR_OFFSET(buf, MAIL_CACHE_FIELD_NAMES(fields.fields_count));

	if ((unsigned int)(names - (const char *)buf) >= fields.size)
		i_fatal("Fields go outside allocated size");

	i_array_init(&cache_fields, 64);
	memset(&field, 0, sizeof(field));
	for (i = 0; i < fields.fields_count; i++) {
		field.name = names;

		field.field_size = size[i];
		field.type = type[i];
		field.decision = decision[i];
		array_append(&cache_fields, &field, 1);

		printf("%u: name=%s size=%u type=%u decision=%u last_used=%u\n",
		       i, names, size[i], type[i], decision[i], last_used[i]);
		names += strlen(names) + 1;
	}
}

static void dump_cache(uint32_t offset)
{
	const struct mail_cache_field *fields;
	struct mail_cache_record rec;
	ssize_t ret;
	char *buf;
	unsigned int idx, size, pos, next_pos, cache_fields_count;
	string_t *str;

	if (offset == 0 || cache_fd == -1)
		return;

	ret = pread(cache_fd, &rec, sizeof(rec), offset);
	if (ret != sizeof(rec)) {
		printf(" - cache at %u BROKEN: points outside file\n", offset);
		return;
	}

	if (rec.size > 1000000) {
		printf(" - cache at %u BROKEN: rec.size = %u\n",
		       offset, rec.size);
		return;
	}

	if (offset <= cache_search_offset &&
	    offset + rec.size > cache_search_offset)
		printf(" - SEARCH MATCH\n");

	buf = t_malloc(rec.size);
	ret = pread(cache_fd, buf, rec.size, offset);
	if (ret != (ssize_t)rec.size)
		i_fatal("cache rec read() %"PRIuSIZE_T" != %u", ret, rec.size);
	printf(" - cache at %u + %u (prev_offset = %u)\n",
	       offset, rec.size, rec.prev_offset);

	fields = array_get(&cache_fields, &cache_fields_count);
	str = t_str_new(512);
	for (pos = sizeof(rec); pos < rec.size; ) {
		idx = *((const uint32_t *)(buf+pos));
		pos += sizeof(uint32_t);

		if (idx >= cache_fields_count) {
			printf("BROKEN: file_field = %u > %u\n",
			       idx, cache_fields_count);
			return;
		}

		size = fields[idx].field_size;
		if (size == (unsigned int)-1) {
			size = *((const uint32_t *)(buf+pos));
			pos += sizeof(uint32_t);
		}

		next_pos = pos + ((size + 3) & ~3);
		if (size > rec.size || next_pos > rec.size) {
			printf("BROKEN: record continues outside its allocated size\n");
			return;
		}

		str_truncate(str, 0);
		str_printfa(str, "    - %s: ", fields[idx].name);
		switch (fields[idx].type) {
		case MAIL_CACHE_FIELD_FIXED_SIZE:
			if (size == sizeof(uint32_t)) {
				str_printfa(str, "%u", *((const uint32_t *)(buf+pos)));
				break;
			}
		case MAIL_CACHE_FIELD_VARIABLE_SIZE:
		case MAIL_CACHE_FIELD_BITMASK:
			str_printfa(str, " (%s)", binary_to_hex((const unsigned char *)buf+pos, size));
			break;
		case MAIL_CACHE_FIELD_STRING:
			if (size > 0)
				str_printfa(str, "%.*s", (int)size, buf+pos);
			break;
		case MAIL_CACHE_FIELD_HEADER: {
			const uint32_t *lines = (void *)(buf + pos);
			int i;

			for (i = 0;; i++) {
				if (size < sizeof(uint32_t)) {
					if (i == 0 && size == 0) {
						/* header doesn't exist */
						break;
					}

					str_append(str, "\n - BROKEN: header field doesn't end with 0 line");
					size = 0;
					break;
				}

				size -= sizeof(uint32_t);
				pos += sizeof(uint32_t);
				if (lines[i] == 0)
					break;

				if (i > 0)
					str_append(str, ", ");
				str_printfa(str, "%u", lines[i]);
			}

			if (i == 1 && size > 0 && buf[pos+size-1] == '\n') size--;
			if (size > 0)
				str_printfa(str, ": %.*s", (int)size, buf+pos);
			break;
		}
		case MAIL_CACHE_FIELD_COUNT:
			i_unreached();
			break;
		}

		printf("%s\n", str_c(str));
		pos = next_pos;
	}

	dump_cache(rec.prev_offset);
}

static int dump_record(int fd, void *buf, unsigned int seq)
{
	off_t offset;
	ssize_t ret;
	const struct mail_index_record *rec = buf;
	const struct mail_index_ext *ext;
	const void *ptr;
	unsigned int i, ext_count;
	string_t *str;

	ret = read(fd, buf, hdr.record_size);
	if (ret == 0)
		return 0;

	if (ret != (ssize_t)hdr.record_size) {
		i_fatal("rec hdr read() %"PRIuSIZE_T" != %u",
			ret, hdr.record_size);
	}

	offset = lseek(fd, 0, SEEK_CUR);

	printf("RECORD: offset=%"PRIuUOFF_T", seq=%u, uid=%u, flags=%x\n",
	       offset, seq, rec->uid, rec->flags);
	str = t_str_new(256);
	ext = array_get(&extensions, &ext_count);
	for (i = 0; i < ext_count; i++) {
		str_truncate(str, 0);
		str_printfa(str, " - ext %s(%u): ", ext[i].name, i);

		ptr = CONST_PTR_OFFSET(buf, ext[i].record_offset);
		if (ext[i].record_size == sizeof(uint32_t) &&
		    ext[i].record_align == sizeof(uint32_t))
			str_printfa(str, "%u", *((const uint32_t *)ptr));
		else if (ext[i].record_size == sizeof(uint64_t) &&
			 ext[i].record_align == sizeof(uint64_t)) {
			uint64_t value = *((const uint64_t *)ptr);
			str_printfa(str, "%llu", (unsigned long long)value);
		}
		str_printfa(str, " (%s)", binary_to_hex(ptr, ext[i].record_size));
		printf("%s\n", str_c(str));

		if (i == cache_ext)
			dump_cache(*((const uint32_t *)ptr));
	}
	return 1;
}

int main(int argc, const char *argv[])
{
	unsigned int seq;
	void *buf;
	int fd, ret;

	lib_init();

	if (argc < 2)
		i_fatal("Usage: idxview dovecot.index [dovecot.index.cache]");

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		i_error("open(): %m");
		return 1;
	}

	printf("-- INDEX: %s\n", argv[1]);

	dump_hdr(fd);
	lseek(fd, hdr.header_size, SEEK_SET);

	printf("---------------\n");

	if (argv[2] != NULL) {
		cache_fd = open(argv[2], O_RDONLY);
		if (cache_fd < 0) {
			i_error("open(): %m");
			return 1;
		}

		dump_cache_hdr(cache_fd);

		printf("---------------\n");

		if (argv[3] != NULL)
			cache_search_offset = atoi(argv[3]);
	}

	buf = i_malloc(hdr.record_size);
	seq = 1;
	do {
		t_push();
		ret = dump_record(fd, buf, seq);
		t_pop();
		seq++;
	} while (ret);
	return 0;
}
