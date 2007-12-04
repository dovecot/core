/* Copyright (c) 2007 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mail-index-private.h"
#include "mail-transaction-log.h"

#include <stdio.h>

static struct mail_transaction_ext_intro prev_intro;

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

static void dump_hdr(int fd)
{
	struct mail_transaction_log_header hdr;
	ssize_t ret;

	ret = read(fd, &hdr, sizeof(hdr));
	if (ret != sizeof(hdr)) {
		i_fatal("file hdr read() %"PRIuSIZE_T" != %"PRIuSIZE_T,
			ret, sizeof(hdr));
	}

	printf("version = %u.%u\n", hdr.major_version, hdr.minor_version);
	printf("hdr size = %u\n", hdr.hdr_size);
	printf("index id = %u\n", hdr.indexid);
	printf("file seq = %u\n", hdr.file_seq);
	printf("prev file = %u/%u\n", hdr.prev_file_seq, hdr.prev_file_offset);
	printf("create stamp = %u\n", hdr.create_stamp);
}

static const char *log_record_type(unsigned int type)
{
	const char *name;

	switch (type & MAIL_TRANSACTION_TYPE_MASK) {
	case MAIL_TRANSACTION_EXPUNGE|MAIL_TRANSACTION_EXPUNGE_PROT:
		name = "expunge";
		break;
	case MAIL_TRANSACTION_APPEND:
		name = "append";
		break;
	case MAIL_TRANSACTION_FLAG_UPDATE:
		name = "flag-update";
		break;
	case MAIL_TRANSACTION_HEADER_UPDATE:
		name = "header-update";
		break;
	case MAIL_TRANSACTION_EXT_INTRO:
		name = "ext-intro";
		break;
	case MAIL_TRANSACTION_EXT_RESET:
		name = "ext-reset";
		break;
	case MAIL_TRANSACTION_EXT_HDR_UPDATE:
		name = "ext-hdr";
		break;
	case MAIL_TRANSACTION_EXT_REC_UPDATE:
		name = "ext-rec";
		break;
	case MAIL_TRANSACTION_KEYWORD_UPDATE:
		name = "keyword-update";
		break;
	case MAIL_TRANSACTION_KEYWORD_RESET:
		name = "keyword-reset";
		break;
	default:
		name = t_strdup_printf("unknown: %x", type);
		break;
	}

	if (type & MAIL_TRANSACTION_EXTERNAL)
		name = t_strconcat(name, " (ext)", NULL);
	return name;
}

static void print_data(const void *data, size_t size)
{
	size_t i;

	for (i = 0; i < size; i++)
		printf("%02x", ((const unsigned char *)data)[i]);
	if (size == 4) {
		const uint32_t *n = (const uint32_t *)data;

		printf(" (dec=%u)", *n);
	}
}

static void log_record_print(const struct mail_transaction_header *hdr,
			     const void *data)
{
	unsigned int size = hdr->size - sizeof(*hdr);

	switch (hdr->type & MAIL_TRANSACTION_TYPE_MASK) {
	case MAIL_TRANSACTION_EXPUNGE|MAIL_TRANSACTION_EXPUNGE_PROT: {
		const struct mail_transaction_expunge *exp = data;

		printf(" -");
		for (; size > 0; size -= sizeof(*exp), exp++) {
			printf(" %u-%u", exp->uid1, exp->uid2);
		}
		printf("\n");
		break;
	}
	case MAIL_TRANSACTION_APPEND: {
		const struct mail_index_record *rec = data;

		printf(" - ");
		for (; size > 0; size -= sizeof(*rec), rec++) {
			printf("%u", rec->uid);
			if (rec->flags != 0)
				printf(" (flags=%x)", rec->flags);
			printf(",");
		}
		printf("\n");
		break;
	}
	case MAIL_TRANSACTION_FLAG_UPDATE: {
		const struct mail_transaction_flag_update *u = data;

		for (; size > 0; size -= sizeof(*u), u++) {
			printf(" - %u-%u (flags +%x-%x)\n", u->uid1, u->uid2,
			       u->add_flags, u->remove_flags);
		}
		break;
	}
	case MAIL_TRANSACTION_HEADER_UPDATE: {
		const struct mail_transaction_header_update *u = data;

		if (u->offset == offsetof(struct mail_index_header,
					  log_file_tail_offset) &&
		    u->size == sizeof(uint32_t)) {
			printf(" - log_file_tail_offset = %u\n",
			       *(const uint32_t *)(u + 1));
			break;
		}
		printf(" - offset = %u, size = %u: ", u->offset, u->size);
		print_data(u + 1, u->size);
		printf("\n");
		break;
	}
	case MAIL_TRANSACTION_EXT_INTRO: {
		const struct mail_transaction_ext_intro *intro = data;

		prev_intro = *intro;
		printf(" - ext_id = %u\n", intro->ext_id);
		printf(" - reset_id = %u\n", intro->reset_id);
		printf(" - hdr_size = %u\n", intro->hdr_size);
		printf(" - record_size = %u\n", intro->record_size);
		printf(" - record_align = %u\n", intro->record_align);
		printf(" - name_size = %u\n", intro->name_size);
		if (intro->name_size > 0) {
			printf(" - name = '%.*s'\n",
			       intro->name_size, (const char *)(intro+1));
		}
		break;
	}
	case MAIL_TRANSACTION_EXT_RESET: {
		const struct mail_transaction_ext_reset *reset = data;

		printf(" - new_reset_id = %u\n", reset->new_reset_id);
		break;
	}
	case MAIL_TRANSACTION_EXT_HDR_UPDATE: {
		const struct mail_transaction_ext_hdr_update *u = data;

		printf(" - offset = %u, size = %u: ", u->offset, u->size);
		print_data(u + 1, u->size);
		printf("\n");
		break;
	}
	case MAIL_TRANSACTION_EXT_REC_UPDATE: {
		const struct mail_transaction_ext_rec_update *rec = data, *end;
		size_t record_size;

		end = CONST_PTR_OFFSET(data, size);
		record_size = (sizeof(*rec) + prev_intro.record_size + 3) & ~3;
		while (rec < end) {
			printf(" - %u: ", rec->uid);
			print_data(rec + 1, prev_intro.record_size);
			printf("\n");
			rec = CONST_PTR_OFFSET(rec, record_size);
		}
		break;
	}
	case MAIL_TRANSACTION_KEYWORD_UPDATE: {
		const struct mail_transaction_keyword_update *u = data;
		const uint32_t *uid;
		unsigned int uid_offset;

		printf(" - modify=%d, name=%.*s, ",
		       u->modify_type, u->name_size, (const char *)(u+1));

		uid_offset = sizeof(*u) + u->name_size +
			((u->name_size % 4) == 0 ? 0 : 4 - (u->name_size%4));
		uid = (const uint32_t *)((const char *)u + uid_offset);
		size -= uid_offset;

		for (; size > 0; size -= sizeof(*uid)*2, uid += 2) {
			printf("%u-%u,", uid[0], uid[1]);
		}
		printf("\n");
		break;
	}
	case MAIL_TRANSACTION_KEYWORD_RESET: {
		const struct mail_transaction_keyword_reset *u = data;

		printf(" - ");
		for (; size > 0; size -= sizeof(*u), u++) {
			printf("%u-%u, ", u->uid1, u->uid2);
		}
		printf("\n");
		break;
	}
	default:
		break;
	}
}

static int dump_record(int fd)
{
	off_t offset;
	ssize_t ret;
	struct mail_transaction_header hdr;
	unsigned int orig_size;

	offset = lseek(fd, 0, SEEK_CUR);

	ret = read(fd, &hdr, sizeof(hdr));
	if (ret == 0)
		return 0;

	if (ret != sizeof(hdr)) {
		i_fatal("rec hdr read() %"PRIuSIZE_T" != %"PRIuSIZE_T,
			ret, sizeof(hdr));
	}

	orig_size = hdr.size;
	hdr.size = mail_index_offset_to_uint32(hdr.size);
	if (hdr.size == 0) {
		printf("record: offset=%"PRIuUOFF_T", "
		       "type=%s, size=broken (%x)\n",
		       offset, log_record_type(hdr.type), orig_size);
		return 0;
	}

	printf("record: offset=%"PRIuUOFF_T", type=%s, size=%u\n",
	       offset, log_record_type(hdr.type), hdr.size);

	if (hdr.size < 1024*1024) {
		unsigned char *buf = t_malloc(hdr.size);

		ret = read(fd, buf, hdr.size - sizeof(hdr));
		if (ret != (ssize_t)(hdr.size - sizeof(hdr))) {
			i_fatal("rec data read() %"PRIuSIZE_T" != %"PRIuSIZE_T,
				ret, hdr.size - sizeof(hdr));
		}
		log_record_print(&hdr, buf);
	} else {
		lseek(fd, hdr.size - sizeof(hdr), SEEK_CUR);
	}
	return 1;
}

int main(int argc, const char *argv[])
{
	int fd;

	lib_init();

	if (argc < 2)
		i_fatal("Usage: logview dovecot.index.log");

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		i_error("open(): %m");
		return 1;
	}

	dump_hdr(fd);
	for (;;) {
		t_push();
		if (!dump_record(fd))
			break;
		t_pop();
	}
	t_pop();
	return 0;
}
