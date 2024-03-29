/* Copyright (c) 2007-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "hex-binary.h"
#include "mail-index-private.h"
#include "mail-transaction-log-private.h"
#include "doveadm-dump.h"

#include <stdio.h>

static struct mail_transaction_ext_intro prev_intro;

static void dump_hdr(struct istream *input, uint64_t *modseq_r,
		     unsigned int *version_r)
{
	struct mail_transaction_log_header hdr;
	const unsigned char *data;
	size_t size;
	int ret;

	ret = i_stream_read_bytes(input, &data, &size, sizeof(hdr));
	if (ret < 0 && input->stream_errno != 0)
		i_fatal("read() failed: %s", i_stream_get_error(input));
	if (ret <= 0) {
		i_fatal("file hdr read() %zu != %zu",
			size, sizeof(hdr));
	}
	memcpy(&hdr, data, sizeof(hdr));
	if (hdr.hdr_size < sizeof(hdr)) {
		memset(PTR_OFFSET(&hdr, hdr.hdr_size), 0,
		       sizeof(hdr) - hdr.hdr_size);
	}
	i_stream_skip(input, hdr.hdr_size);

	printf("version = %u.%u\n", hdr.major_version, hdr.minor_version);
	printf("hdr size = %u\n", hdr.hdr_size);
	printf("index id = %u\n", hdr.indexid);
	printf("file seq = %u\n", hdr.file_seq);
	printf("prev file = %u/%u\n", hdr.prev_file_seq, hdr.prev_file_offset);
	printf("create stamp = %u\n", hdr.create_stamp);
	printf("initial modseq = %"PRIu64"\n", hdr.initial_modseq);
	printf("compat flags = %x\n", hdr.compat_flags);
	*modseq_r = hdr.initial_modseq;
	*version_r = MAIL_TRANSACTION_LOG_HDR_VERSION(&hdr);
}

static const char *log_record_type(unsigned int type)
{
	const char *name;

	switch (type & MAIL_TRANSACTION_TYPE_MASK) {
	case MAIL_TRANSACTION_EXPUNGE|MAIL_TRANSACTION_EXPUNGE_PROT:
		name = "expunge";
		break;
	case MAIL_TRANSACTION_EXPUNGE_GUID|MAIL_TRANSACTION_EXPUNGE_PROT:
		name = "expunge-guid";
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
	case MAIL_TRANSACTION_EXT_HDR_UPDATE32:
		name = "ext-hdr32";
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
	case MAIL_TRANSACTION_EXT_ATOMIC_INC:
		name = "ext-atomic-inc";
		break;
	case MAIL_TRANSACTION_MODSEQ_UPDATE:
		name = "modseq-update";
		break;
	case MAIL_TRANSACTION_INDEX_DELETED:
		name = "index-deleted";
		break;
	case MAIL_TRANSACTION_INDEX_UNDELETED:
		name = "index-undeleted";
		break;
	case MAIL_TRANSACTION_BOUNDARY:
		name = "boundary";
		break;
	case MAIL_TRANSACTION_ATTRIBUTE_UPDATE:
		name = "attribute-update";
		break;
	default:
		name = t_strdup_printf("unknown: %x", type);
		break;
	}

	if ((type & MAIL_TRANSACTION_EXTERNAL) != 0)
		name = t_strconcat(name, " (ext)", NULL);
	if ((type & MAIL_TRANSACTION_SYNC) != 0)
		name = t_strconcat(name, " (sync)", NULL);
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

static void print_try_uint(const void *data, size_t size)
{
	size_t i;

	switch (size) {
	case 1: {
		const uint8_t *n = data;
		printf("%u", *n);
		break;
	}
	case 2: {
		const uint16_t *n = data;
		uint32_t n16;

		memcpy(&n16, n, sizeof(n16));
		printf("%u", n16);
		break;
	}
	case 4: {
		const uint32_t *n = data;
		uint32_t n32;

		memcpy(&n32, n, sizeof(n32));
		printf("%u", n32);
		break;
	}
	case 8: {
		const uint64_t *n = data;
		uint64_t n64;

		memcpy(&n64, n, sizeof(n64));
		printf("%"PRIu64, n64);
		break;
	}
	default:
		for (i = 0; i < size; i++)
			printf("%02x", ((const unsigned char *)data)[i]);
	}
}

#define HDRF(field) { \
	#field, offsetof(struct mail_index_header, field), \
	sizeof(((struct mail_index_header *)0)->field) }

static struct {
	const char *name;
	unsigned int offset, size;
} header_fields[] = {
	HDRF(minor_version),
	HDRF(base_header_size),
	HDRF(header_size),
	HDRF(record_size),
	HDRF(compat_flags),
	HDRF(indexid),
	HDRF(flags),
	HDRF(uid_validity),
	HDRF(next_uid),
	HDRF(messages_count),
	HDRF(unused_old_recent_messages_count),
	HDRF(seen_messages_count),
	HDRF(deleted_messages_count),
	HDRF(first_recent_uid),
	HDRF(first_unseen_uid_lowwater),
	HDRF(first_deleted_uid_lowwater),
	HDRF(log_file_seq),
	HDRF(log_file_tail_offset),
	HDRF(log_file_head_offset),
	HDRF(day_stamp)
};

static void log_header_update(const struct mail_transaction_header_update *u,
			      size_t data_size)
{
	const void *data = u + 1;
	unsigned int offset = u->offset, size = u->size;
	unsigned int i;

	if (sizeof(*u) + size > data_size) {
		printf(" - offset = %u, size = %u (too large)\n", offset, size);
		return;
	}

	while (size > 0) {
		/* don't bother trying to handle header updates that include
		   unknown/unexpected fields offsets/sizes */
		for (i = 0; i < N_ELEMENTS(header_fields); i++) {
			if (header_fields[i].offset == offset &&
			    header_fields[i].size <= size)
				break;
		}

		if (i == N_ELEMENTS(header_fields)) {
			printf(" - offset = %u, size = %u: ", offset, size);
			print_data(data, size);
			printf("\n");
			break;
		}

		printf(" - %s = ", header_fields[i].name);
		print_try_uint(data, header_fields[i].size);
		printf("\n");

		data = CONST_PTR_OFFSET(data, header_fields[i].size);
		offset += header_fields[i].size;
		size -= header_fields[i].size;
	}
}

static void log_record_print(const struct mail_transaction_header *hdr,
			     const void *data, size_t data_size,
			     uint64_t *modseq)
{
	unsigned int size = mail_index_offset_to_uint32(hdr->size) - sizeof(*hdr);

	switch (hdr->type & MAIL_TRANSACTION_TYPE_MASK) {
	case MAIL_TRANSACTION_EXPUNGE|MAIL_TRANSACTION_EXPUNGE_PROT: {
		const struct mail_transaction_expunge *exp = data;

		printf(" - uids=");
		for (; size > 0; size -= sizeof(*exp), exp++) {
			printf("%u-%u,", exp->uid1, exp->uid2);
		}
		printf("\n");
		break;
	}
	case MAIL_TRANSACTION_EXPUNGE_GUID|MAIL_TRANSACTION_EXPUNGE_PROT: {
		const struct mail_transaction_expunge_guid *exp = data;

		for (; size > 0; size -= sizeof(*exp), exp++) {
			printf(" - uid=%u (guid ", exp->uid);
			print_data(exp->guid_128, sizeof(exp->guid_128));
			printf(")\n");
		}
		break;
	}
	case MAIL_TRANSACTION_APPEND: {
		const struct mail_index_record *rec = data;

		printf(" - uids=");
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
			printf(" - uids=%u-%u (flags +%x-%x, modseq_inc_flag=%d)\n",
			       u->uid1, u->uid2, u->add_flags, u->remove_flags, u->modseq_inc_flag);
		}
		break;
	}
	case MAIL_TRANSACTION_HEADER_UPDATE: {
		const struct mail_transaction_header_update *u = data;

		log_header_update(u, data_size);
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
		printf(" - flags = %u\n", intro->flags);
		printf(" - name_size = %u\n", intro->name_size);
		if (intro->name_size > 0) {
			const char *name = (const char *)(intro+1);

			printf(" - name = '%.*s'\n", intro->name_size, name);
			if (*modseq == 0 && intro->name_size == 6 &&
			    memcmp(name, "modseq", 6) == 0)
				*modseq = 1;
		}
		break;
	}
	case MAIL_TRANSACTION_EXT_RESET: {
		const struct mail_transaction_ext_reset *reset = data;

		printf(" - new_reset_id = %u\n", reset->new_reset_id);
		printf(" - preserve_data = %u\n", reset->preserve_data);
		break;
	}
	case MAIL_TRANSACTION_EXT_HDR_UPDATE: {
		const struct mail_transaction_ext_hdr_update *u = data;

		printf(" - offset = %u, size = %u", u->offset, u->size);
		if (sizeof(*u) + u->size <= data_size) {
			printf(": ");
			print_data(u + 1, u->size);
		} else {
			printf(" (too large)");
		}
		printf("\n");
		break;
	}
	case MAIL_TRANSACTION_EXT_HDR_UPDATE32: {
		const struct mail_transaction_ext_hdr_update32 *u = data;

		printf(" - offset = %u, size = %u", u->offset, u->size);
		if (sizeof(*u) + u->size <= data_size) {
			printf(": ");
			print_data(u + 1, u->size);
		} else {
			printf(" (too large)");
		}
		printf("\n");
		break;
	}
	case MAIL_TRANSACTION_EXT_REC_UPDATE: {
		const struct mail_transaction_ext_rec_update *rec = data, *end;
		size_t record_size;

		end = CONST_PTR_OFFSET(data, size);
		record_size = (sizeof(*rec) + prev_intro.record_size + 3) & ~3U;
		while (rec < end) {
			printf(" - uid=%u: ", rec->uid);
			size_t bytes_left = (const char *)end - (const char *)(rec + 1);
			if (prev_intro.record_size <= bytes_left)
				print_data(rec + 1, prev_intro.record_size);
			else
				printf("(record_size too large)");
			printf("\n");
			rec = CONST_PTR_OFFSET(rec, record_size);
		}
		break;
	}
	case MAIL_TRANSACTION_EXT_ATOMIC_INC: {
		const struct mail_transaction_ext_atomic_inc *rec = data, *end;

		end = CONST_PTR_OFFSET(data, size);
		for (; rec < end; rec++) {
			printf(" - uid=%u: ", rec->uid);
			if (rec->diff > 0)
				printf("+%d\n", rec->diff);
			else
				printf("%d\n", rec->diff);
		}
		break;
	}
	case MAIL_TRANSACTION_KEYWORD_UPDATE: {
		const struct mail_transaction_keyword_update *u = data;
		const uint32_t *uid;
		unsigned int uid_offset;

		printf(" - modify=%d, name=%.*s, uids=",
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

		printf(" - uids=");
		for (; size > 0; size -= sizeof(*u), u++) {
			printf("%u-%u, ", u->uid1, u->uid2);
		}
		printf("\n");
		break;
	}
	case MAIL_TRANSACTION_MODSEQ_UPDATE: {
		const struct mail_transaction_modseq_update *rec, *end;

		end = CONST_PTR_OFFSET(data, size);
		for (rec = data; rec < end; rec++) {
			printf(" - uid=%u modseq=%"PRIu64"\n", rec->uid,
			       ((uint64_t)rec->modseq_high32 << 32) |
			       rec->modseq_low32);
		}
		break;
	}
	case MAIL_TRANSACTION_INDEX_DELETED:
	case MAIL_TRANSACTION_INDEX_UNDELETED:
		break;
	case MAIL_TRANSACTION_BOUNDARY: {
		const struct mail_transaction_boundary *rec = data;

		printf(" - size=%u\n", rec->size);
		break;
	}
	case MAIL_TRANSACTION_ATTRIBUTE_UPDATE: {
		const char *keys = data;
		const uint32_t *extra;
		unsigned int i, extra_pos, extra_count = 0;

		for (i = 0; i < size && keys[i] != '\0'; ) {
			if (keys[i] == '+')
				extra_count++;
			extra_count++;
			i += strlen(keys+i) + 1;
		}
		if (i % sizeof(uint32_t) != 0)
			i += sizeof(uint32_t) - i%sizeof(uint32_t);
		extra = (const void *)(keys+i);

		if ((size-i) != extra_count*sizeof(uint32_t)) {
			printf(" - broken entry\n");
			break;
		}

		extra_pos = 0;
		for (i = 0; i < size && keys[i] != '\0'; ) {
			printf(" - %s: %s/%s : timestamp=%s",
			       keys[i] == '+' ? "add" : keys[i] == '-' ? "remove" : "?",
			       keys[i+1] == 'p' ? "private" :
			       keys[i+1] == 's' ? "shared" : "?error?",
			       keys+i+2, unixdate2str(extra[extra_pos++]));
			if (keys[i] == '+')
				printf(" value_len=%u", extra[extra_pos++]);
			printf("\n");
			i += strlen(keys+i) + 1;
		}

		break;
	}
	default:
		break;
	}
}

static int dump_record(struct istream *input, uint64_t *modseq,
		       unsigned int version)
{
	struct mail_transaction_header hdr;
	unsigned int hdr_size;
	const unsigned char *data;
	size_t size;
	int ret;

	ret = i_stream_read_bytes(input, &data, &size, sizeof(hdr));
	if (ret < 0 && input->stream_errno != 0)
		i_fatal("read() failed: %s", i_stream_get_error(input));
	if (ret <= 0) {
		if (size == 0)
			return 0;
		i_fatal("rec hdr read() %zu != %zu",
			size, sizeof(hdr));
	}
	memcpy(&hdr, data, sizeof(hdr));

	hdr_size = mail_index_offset_to_uint32(hdr.size);
	if (hdr_size < sizeof(hdr)) {
		printf("record: offset=%"PRIuUOFF_T", "
		       "type=%s, size=broken (%x)\n",
		       input->v_offset, log_record_type(hdr.type), hdr.size);
		return 0;
	}

	printf("record: offset=%"PRIuUOFF_T", type=%s, size=%u",
	       input->v_offset, log_record_type(hdr.type), hdr_size);

	i_stream_skip(input, sizeof(hdr));
	size_t data_size = hdr_size - sizeof(hdr);
	ret = i_stream_read_bytes(input, &data, &size, data_size);
	if (ret < 0 && input->stream_errno != 0)
		i_fatal("read() failed: %s", i_stream_get_error(input));
	if (ret <= 0) {
		i_fatal("rec data read() %zu != %zu",
			size, data_size);
	}

	uint64_t prev_modseq = *modseq;
	mail_transaction_update_modseq(&hdr, data, modseq, version);
	if (*modseq > prev_modseq)
		printf(", modseq=%"PRIu64, *modseq);
	printf("\n");

	log_record_print(&hdr, data, data_size, modseq);
	i_stream_skip(input, data_size);
	return 1;
}

static void cmd_dump_log(struct doveadm_cmd_context *cctx ATTR_UNUSED,
			 const char *path, const char *const *args ATTR_UNUSED)
{
	struct istream *input;
	uint64_t modseq;
	unsigned int version;
	int ret;

	input = i_stream_create_file(path, SIZE_MAX);
	dump_hdr(input, &modseq, &version);
	do {
		T_BEGIN {
			ret = dump_record(input, &modseq, version);
		} T_END;
	} while (ret > 0);
	i_stream_unref(&input);
}

static bool test_dump_log(struct doveadm_cmd_context *cctx ATTR_UNUSED,
			  const char *path)
{
	struct mail_transaction_log_header hdr;
	const char *p;
	bool ret = FALSE;
	int fd;

	p = strrchr(path, '/');
	if (p == NULL)
		p = path;
	p = strstr(p, ".log");
	if (p == NULL || !(p[4] == '\0' || p[4] == '.'))
		return FALSE;

	fd = open(path, O_RDONLY);
	if (fd == -1)
		return FALSE;

	if (read(fd, &hdr, sizeof(hdr)) >= MAIL_TRANSACTION_LOG_HEADER_MIN_SIZE &&
	    hdr.major_version == MAIL_TRANSACTION_LOG_MAJOR_VERSION &&
	    hdr.hdr_size >= MAIL_TRANSACTION_LOG_HEADER_MIN_SIZE)
		ret = TRUE;
	i_close_fd(&fd);
	return ret;
}

struct doveadm_cmd_dump doveadm_cmd_dump_log = {
	"log",
	test_dump_log,
	cmd_dump_log
};
