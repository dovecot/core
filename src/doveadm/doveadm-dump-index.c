/* Copyright (c) 2007-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "hex-binary.h"
#include "file-lock.h"
#include "message-parser.h"
#include "message-part-serialize.h"
#include "mail-index-private.h"
#include "mail-cache-private.h"
#include "mail-index-modseq.h"
#include "doveadm-dump.h"

#include <stdio.h>
#include <time.h>

struct index_vsize_header {
	uint64_t vsize;
	uint32_t highest_uid;
	uint32_t message_count;
};
struct maildir_index_header {
	uint32_t new_check_time, new_mtime, new_mtime_nsecs;
	uint32_t cur_check_time, cur_mtime, cur_mtime_nsecs;
	uint32_t uidlist_mtime, uidlist_mtime_nsecs, uidlist_size;
};
struct mbox_index_header {
	uint64_t sync_size;
	uint32_t sync_mtime;
	uint8_t dirty_flag;
	uint8_t unused[3];
	uint8_t mailbox_guid[16];
};
struct sdbox_index_header {
	uint32_t rebuild_count;
	guid_128_t mailbox_guid;
	uint8_t flags;
	uint8_t unused[3];
};
struct mdbox_index_header {
	uint32_t map_uid_validity;
	guid_128_t mailbox_guid;
	uint8_t flags;
	uint8_t unused[3];
};
struct mdbox_mail_index_record {
	uint32_t map_uid;
	uint32_t save_date;
};
struct obox_mail_index_record {
	unsigned char guid[GUID_128_SIZE];
	unsigned char oid[GUID_128_SIZE];
};
struct mobox_mail_index_header {
	uint32_t rebuild_count;
	uint32_t map_uid_validity;
	uint8_t unused[4];
	guid_128_t mailbox_guid;
};
struct mobox_mail_index_record {
	uint32_t map_uid;
	uint32_t save_date;
};
struct mobox_map_mail_index_header {
	uint32_t rebuild_count;
};

struct mobox_map_mail_index_record {
	uint32_t offset;
	uint32_t size;
	guid_128_t oid;
};
struct mailbox_list_index_header {
	uint8_t refresh_flag;
	/* array of { uint32_t id; char name[]; } */
};
struct mailbox_list_index_record {
	uint32_t name_id;
	uint32_t parent_uid;
	guid_128_t guid;
	uint32_t uid_validity;
};
struct mailbox_list_index_msgs_record {
	uint32_t messages;
	uint32_t unseen;
	uint32_t recent;
	uint32_t uidnext;
};
struct mailbox_index_vsize {
	uint64_t vsize;
	uint32_t highest_uid;
	uint32_t message_count;
};

struct fts_index_header {
	uint32_t last_indexed_uid;
	uint32_t settings_checksum;
	uint32_t unused;
};
struct virtual_mail_index_header {
	uint32_t change_counter;
	uint32_t mailbox_count;
	uint32_t highest_mailbox_id;
	uint32_t search_args_crc32;
};
struct virtual_mail_index_mailbox_record {
	uint32_t id;
	uint32_t name_len;
	uint32_t uid_validity;
	uint32_t next_uid;
	uint64_t highest_modseq;
};
struct virtual_mail_index_record {
	uint32_t mailbox_id;
	uint32_t real_uid;
};

struct mdbox_mail_index_map_record {
	uint32_t file_id;
	uint32_t offset;
	uint32_t size;
};

static void dump_hdr(struct mail_index *index)
{
	const struct mail_index_header *hdr = &index->map->hdr;
	unsigned int i;

	printf("version .................. = %u.%u\n", hdr->major_version, hdr->minor_version);
	printf("base header size ......... = %u\n", hdr->base_header_size);
	printf("header size .............. = %u\n", hdr->header_size);
	printf("record size .............. = %u\n", hdr->record_size);
	printf("compat flags ............. = %u\n", hdr->compat_flags);
	printf("index id ................. = %u (%s)\n", hdr->indexid, unixdate2str(hdr->indexid));
	printf("flags .................... = %u\n", hdr->flags);
	printf("uid validity ............. = %u (%s)\n", hdr->uid_validity, unixdate2str(hdr->uid_validity));
	printf("next uid ................. = %u\n", hdr->next_uid);
	printf("messages count ........... = %u\n", hdr->messages_count);
	printf("seen messages count ...... = %u\n", hdr->seen_messages_count);
	printf("deleted messages count ... = %u\n", hdr->deleted_messages_count);
	printf("first recent uid ......... = %u\n", hdr->first_recent_uid);
	printf("first unseen uid lowwater  = %u\n", hdr->first_unseen_uid_lowwater);
	printf("first deleted uid lowwater = %u\n", hdr->first_deleted_uid_lowwater);
	printf("log file seq ............. = %u\n", hdr->log_file_seq);
	if (hdr->minor_version == 0) {
		printf("log file int offset ...... = %u\n", hdr->log_file_tail_offset);
		printf("log file ext offset ...... = %u\n", hdr->log_file_head_offset);
	} else {
		printf("log file tail offset ..... = %u\n", hdr->log_file_tail_offset);
		printf("log file head offset ..... = %u\n", hdr->log_file_head_offset);
	}
	if (hdr->minor_version >= 3) {
		printf("log2 rotate time ......... = %u (%s)\n", hdr->log2_rotate_time, unixdate2str(hdr->log2_rotate_time));
		printf("last temp file scan ...... = %u (%s)\n", hdr->last_temp_file_scan, unixdate2str(hdr->last_temp_file_scan));
	}
	printf("day stamp ................ = %u (%s)\n", hdr->day_stamp, unixdate2str(hdr->day_stamp));
	for (i = 0; i < N_ELEMENTS(hdr->day_first_uid); i++)
		printf("day first uid[%u] ......... = %u\n", i, hdr->day_first_uid[i]);
}

static void dump_list_header(const void *data, size_t size)
{
	const struct mailbox_list_index_header *hdr = data;
	const void *name_start, *p;
	size_t i, len;
	uint32_t id;

	printf(" - refresh_flag = %d\n", hdr->refresh_flag);
	for (i = sizeof(*hdr); i < size; ) {
		/* get id */
		if (i + sizeof(id) > size) {
			printf(" - corrupted\n");
			break;
		}
		memcpy(&id, CONST_PTR_OFFSET(data, i), sizeof(id));
		i += sizeof(id);

		if (id == 0)
			break;

		/* get name */
		p = memchr(CONST_PTR_OFFSET(data, i), '\0', size-i);
		if (p == NULL) {
			printf(" - corrupted\n");
			break;
		}
		name_start = CONST_PTR_OFFSET(data, i);
		len = (const char *)p - (const char *)name_start;

		printf(" - %d : %.*s\n", id, (int)len, (const char *)name_start);

		i += len + 1;
	}
}

static void dump_box_name_header(const void *data, size_t size)
{
	char *dest = t_malloc0(size + 1);
	memcpy(dest, data, size);
	for (size_t i = 0; i < size; i++) {
		if (dest[i] == '\0')
			dest[i] = '\n';
	}
	printf(" %s\n", t_strarray_join(t_strsplit(dest, "\n"), "\n "));
}

static void dump_extension_header(struct mail_index *index,
				  const struct mail_index_ext *ext)
{
	const void *data;
	void *buf;

	if (strcmp(ext->name, MAIL_INDEX_EXT_KEYWORDS) == 0)
		return;

	/* add some padding, since we don't bother to handle undersized
	   headers correctly */
	buf = t_malloc0(MALLOC_ADD(ext->hdr_size, 128));
	data = CONST_PTR_OFFSET(index->map->hdr_base, ext->hdr_offset);
	memcpy(buf, data, ext->hdr_size);
	data = buf;

	if (strcmp(ext->name, "hdr-vsize") == 0) {
		const struct index_vsize_header *hdr = data;

		printf("header\n");
		printf(" - highest uid . = %u\n", hdr->highest_uid);
		printf(" - message count = %u\n", hdr->message_count);
		printf(" - vsize ....... = %"PRIu64"\n", hdr->vsize);
	} else if (strcmp(ext->name, "maildir") == 0) {
		const struct maildir_index_header *hdr = data;

		printf("header\n");
		printf(" - new_check_time .... = %s\n", unixdate2str(hdr->new_check_time));
		printf(" - new_mtime ......... = %s\n", unixdate2str(hdr->new_mtime));
		printf(" - new_mtime_nsecs ... = %u\n", hdr->new_mtime_nsecs);
		printf(" - cur_check_time .... = %s\n", unixdate2str(hdr->cur_check_time));
		printf(" - cur_mtime ......... = %s\n", unixdate2str(hdr->cur_mtime));
		printf(" - cur_mtime_nsecs.... = %u\n", hdr->cur_mtime_nsecs);
		printf(" - uidlist_mtime ..... = %s\n", unixdate2str(hdr->uidlist_mtime));
		printf(" - uidlist_mtime_nsecs = %u\n", hdr->uidlist_mtime_nsecs);
		printf(" - uidlist_size ...... = %u\n", hdr->uidlist_size);
	} else if (strcmp(ext->name, "mbox") == 0) {
		const struct mbox_index_header *hdr = data;

		printf("header\n");
		printf(" - sync_mtime . = %s\n", unixdate2str(hdr->sync_mtime));
		printf(" - sync_size .. = %"PRIu64"\n", hdr->sync_size);
		printf(" - dirty_flag . = %d\n", hdr->dirty_flag);
		printf(" - mailbox_guid = %s\n",
		       guid_128_to_string(hdr->mailbox_guid));
	} else if (strcmp(ext->name, "mdbox-hdr") == 0) {
		const struct mdbox_index_header *hdr = data;

		printf("header\n");
		printf(" - map_uid_validity .. = %u\n", hdr->map_uid_validity);
		printf(" - mailbox_guid ...... = %s\n",
		       guid_128_to_string(hdr->mailbox_guid));
		printf(" - flags ............. = 0x%x\n", hdr->flags);
	} else if (strcmp(ext->name, "dbox-hdr") == 0) {
		const struct sdbox_index_header *hdr = data;

		printf("header\n");
		printf(" - rebuild_count . = %u\n", hdr->rebuild_count);
		printf(" - mailbox_guid .. = %s\n",
		       guid_128_to_string(hdr->mailbox_guid));
		printf(" - flags ......... = 0x%x\n", hdr->flags);
	} else if (strcmp(ext->name, "mobox-hdr") == 0) {
		const struct mobox_mail_index_header *hdr = data;

		printf("header\n");
		printf(" - rebuild_count    .. = %u\n", hdr->rebuild_count);
		printf(" - map_uid_validity .. = %u\n", hdr->map_uid_validity);
		printf(" - mailbox_guid ...... = %s\n",
		       guid_128_to_string(hdr->mailbox_guid));
	} else if (strcmp(ext->name, "mobox-map") == 0) {
		const struct mobox_map_mail_index_header *hdr = data;

		printf("header\n");
		printf(" - rebuild_count    .. = %u\n", hdr->rebuild_count);
	} else if (strcmp(ext->name, "modseq") == 0) {
		const struct mail_index_modseq_header *hdr = data;

		printf("header\n");
		printf(" - highest_modseq = %"PRIu64"\n", hdr->highest_modseq);
		printf(" - log_seq ...... = %u\n", hdr->log_seq);
		printf(" - log_offset ... = %u\n", hdr->log_offset);
	} else if (strcmp(ext->name, "fts") == 0) {
		const struct fts_index_header *hdr = data;

		printf("header\n");
		printf(" - last_indexed_uid ..... = %u\n",
		       hdr->last_indexed_uid);
		printf(" - settings_checksum .... = %u\n",
		       hdr->settings_checksum);
	} else if (strcmp(ext->name, "virtual") == 0) {
		const struct virtual_mail_index_header *hdr = data;
		const struct virtual_mail_index_mailbox_record *rec;
		const unsigned char *name;
		unsigned int i;

		printf("header\n");
		printf(" - change_counter ... = %u\n", hdr->change_counter);
		printf(" - mailbox_count .... = %u\n", hdr->mailbox_count);
		printf(" - highest_mailbox_id = %u\n", hdr->highest_mailbox_id);
		printf(" - search_args_crc32  = %u\n", hdr->search_args_crc32);

		rec = CONST_PTR_OFFSET(hdr, sizeof(*hdr));
		name = CONST_PTR_OFFSET(rec, sizeof(*rec) * hdr->mailbox_count);
		for (i = 0; i < hdr->mailbox_count; i++, rec++) {
			printf("mailbox %s:\n", t_strndup(name, rec->name_len));
			printf(" - id ........... = %u\n", rec->id);
			printf(" - uid_validity . = %u\n", rec->uid_validity);
			printf(" - next_uid ..... = %u\n", rec->next_uid);
			printf(" - highest_modseq = %"PRIu64"\n",
			       rec->highest_modseq);

			name += rec->name_len;
		}
	} else if (strcmp(ext->name, "list") == 0) {
		printf("header ........ = %s\n",
		       binary_to_hex(data, ext->hdr_size));
		dump_list_header(data, ext->hdr_size);
	} else if (strcmp(ext->name, "box-name") == 0) {
		printf("header ........ = %s\n",
		       binary_to_hex(data, ext->hdr_size));
		dump_box_name_header(data, ext->hdr_size);
	} else {
		printf("header ........ = %s\n",
		       binary_to_hex(data, ext->hdr_size));
	}
}

static void dump_extensions(struct mail_index *index)
{
	const struct mail_index_ext *extensions;
	unsigned int i, count;

	if (array_is_created(&index->map->extensions))
		extensions = array_get(&index->map->extensions, &count);
	else
		count = 0;
	if (count == 0) {
		printf("no extensions\n");
		return;
	}

	for (i = 0; i < count; i++) {
		const struct mail_index_ext *ext = &extensions[i];

		printf("-- Extension %u --\n", i);
		printf("name ........ = %s\n", ext->name);
		printf("hdr_size .... = %u\n", ext->hdr_size);
		printf("reset_id .... = %u\n", ext->reset_id);
		printf("record_offset = %u\n", ext->record_offset);
		printf("record_size . = %u\n", ext->record_size);
		printf("record_align  = %u\n", ext->record_align);
		if (ext->hdr_size > 0) T_BEGIN {
			dump_extension_header(index, ext);
		} T_END;
	}
}

static void dump_keywords(struct mail_index *index)
{
	const unsigned int *kw_indexes;
	const char *const *keywords;
	unsigned int i, count;

	printf("-- Keywords --\n");
	if (!array_is_created(&index->map->keyword_idx_map))
		return;

	kw_indexes = array_get(&index->map->keyword_idx_map, &count);
	if (count == 0)
		return;

	keywords = array_idx(&index->keywords, 0);
	for (i = 0; i < count; i++)
		printf("%3u = %s\n", i, keywords[kw_indexes[i]]);
}

static const char *cache_decision2str(enum mail_cache_decision_type type)
{
	const char *str;

	switch (type & ~MAIL_CACHE_DECISION_FORCED) {
	case MAIL_CACHE_DECISION_NO:
		str = "no";
		break;
	case MAIL_CACHE_DECISION_TEMP:
		str = "tmp";
		break;
	case MAIL_CACHE_DECISION_YES:
		str = "yes";
		break;
	default:
		return t_strdup_printf("0x%x", type);
	}

	if ((type & MAIL_CACHE_DECISION_FORCED) != 0)
		str = t_strconcat(str, "!", NULL);
	return str;
}

#define CACHE_TYPE_IS_FIXED_SIZE(type) \
	((type) == MAIL_CACHE_FIELD_FIXED_SIZE || \
	 (type) == MAIL_CACHE_FIELD_BITMASK)
static const char *cache_type2str(enum mail_cache_field_type type)
{
	switch (type) {
	case MAIL_CACHE_FIELD_FIXED_SIZE:
		return "fix";
	case MAIL_CACHE_FIELD_VARIABLE_SIZE:
		return "var";
	case MAIL_CACHE_FIELD_STRING:
		return "str";
	case MAIL_CACHE_FIELD_BITMASK:
		return "bit";
	case MAIL_CACHE_FIELD_HEADER:
		return "hdr";
	default:
		return t_strdup_printf("0x%x", type);
	}
}

static void dump_cache_hdr(struct mail_cache *cache)
{
	const struct mail_cache_header *hdr;
	const struct mail_cache_field *fields, *field;
	unsigned int i, count, cache_idx;

	(void)mail_cache_open_and_verify(cache);
	if (MAIL_CACHE_IS_UNUSABLE(cache)) {
		printf("cache is unusable\n");
		return;
	}

	hdr = cache->hdr;
	printf("major version ........ = %u\n", hdr->major_version);
	printf("minor version ........ = %u\n", hdr->minor_version);
	printf("indexid .............. = %u (%s)\n", hdr->indexid, unixdate2str(hdr->indexid));
	printf("file_seq ............. = %u (%s) (%d compressions)\n",
	       hdr->file_seq, unixdate2str(hdr->file_seq),
	       hdr->file_seq - hdr->indexid);
	printf("continued_record_count = %u\n", hdr->continued_record_count);
	printf("record_count ......... = %u\n", hdr->record_count);
	printf("used_file_size (old) . = %u\n", hdr->backwards_compat_used_file_size);
	printf("deleted_record_count . = %u\n", hdr->deleted_record_count);
	printf("field_header_offset .. = %u (0x%08x nontranslated)\n",
	       mail_index_offset_to_uint32(hdr->field_header_offset),
	       hdr->field_header_offset);

	printf("-- Cache fields --\n");
	fields = mail_cache_register_get_list(cache, pool_datastack_create(),
					      &count);
	printf(
" #  Name                                         Type Size Dec  Last used\n");
	for (i = 0; i < cache->file_fields_count; i++) {
		cache_idx = cache->file_field_map[i];
		field = &fields[cache_idx];

		printf("%2u: %-44s %-4s ", i, field->name,
		       cache_type2str(field->type));
		if (field->field_size != (uint32_t)-1 ||
		    CACHE_TYPE_IS_FIXED_SIZE(field->type))
			printf("%4u ", field->field_size);
		else
			printf("   - ");
		printf("%-4s %.16s\n",
		       cache_decision2str(field->decision),
		       unixdate2str(field->last_used));
	}
}

static void dump_message_part(string_t *str, const struct message_part *part)
{
	for (; part != NULL; part = part->next) {
		str_append_c(str, '(');
		str_printfa(str, "pos=%"PRIuUOFF_T" ", part->physical_pos);
		str_printfa(str, "hdr.p=%"PRIuUOFF_T" ", part->header_size.physical_size);
		str_printfa(str, "hdr.v=%"PRIuUOFF_T" ", part->header_size.virtual_size);
		str_printfa(str, "body.p=%"PRIuUOFF_T" ", part->body_size.physical_size);
		str_printfa(str, "body.v=%"PRIuUOFF_T" ", part->body_size.virtual_size);
		str_printfa(str, "flags=%x", part->flags);
		if (part->children != NULL) {
			str_append_c(str, ' ');
			dump_message_part(str, part->children);
		}
		str_append_c(str, ')');
	}
}

static void
dump_cache_mime_parts(string_t *str, const void *data, unsigned int size)
{
	const struct message_part *part;
	const char *error;

	str_append_c(str, ' ');

	part = message_part_deserialize(pool_datastack_create(), data, size, &error);
	if (part == NULL) {
		str_printfa(str, "error: %s", error);
		return;
	}

	dump_message_part(str, part);
}

static void
dump_cache_snippet(string_t *str, const unsigned char *data, unsigned int size)
{
	if (size == 0)
		return;
	str_printfa(str, " (version=%u: ", data[0]);
	str_append_n(str, data+1, size-1);
	str_append_c(str, ')');
}

static void dump_cache(struct mail_cache_view *cache_view, unsigned int seq)
{
	struct mail_cache_lookup_iterate_ctx iter;
	const struct mail_cache_record *prev_rec = NULL;
	const struct mail_cache_field *field;
	struct mail_cache_iterate_field iter_field;
	const void *data;
	unsigned int size;
	string_t *str;
	int ret;

	str = t_str_new(512);
	mail_cache_lookup_iter_init(cache_view, seq, &iter);
	while ((ret = mail_cache_lookup_iter_next(&iter, &iter_field)) > 0) {
		if (iter.rec != prev_rec) {
			printf(" - cache offset=%u size=%u, prev_offset = %u\n",
			       iter.offset, iter.rec->size,
			       iter.rec->prev_offset);
			prev_rec = iter.rec;
		}

		field = &cache_view->cache->fields[iter_field.field_idx].field;
		data = iter_field.data;
		size = iter_field.size;

		str_truncate(str, 0);
		str_printfa(str, "    - %s: ", field->name);
		switch (field->type) {
		case MAIL_CACHE_FIELD_FIXED_SIZE:
			if (size == sizeof(uint32_t)) {
				uint32_t value;
				memcpy(&value, data, sizeof(value));
				str_printfa(str, "%u ", value);
			} else if (size == sizeof(uint64_t)) {
				uint64_t value;
				memcpy(&value, data, sizeof(value));
				str_printfa(str, "%"PRIu64, value);
			}
			/* fall through */
		case MAIL_CACHE_FIELD_VARIABLE_SIZE:
		case MAIL_CACHE_FIELD_BITMASK:
			str_printfa(str, "(%s)", binary_to_hex(data, size));
			if (strcmp(field->name, "mime.parts") == 0)
				dump_cache_mime_parts(str, data, size);
			else if (strcmp(field->name, "body.snippet") == 0)
				dump_cache_snippet(str, data, size);
			break;
		case MAIL_CACHE_FIELD_STRING:
			if (size > 0)
				str_printfa(str, "%.*s", (int)size, (const char *)data);
			break;
		case MAIL_CACHE_FIELD_HEADER: {
			const uint32_t *lines = data;
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
				data = CONST_PTR_OFFSET(data, sizeof(uint32_t));
				if (lines[i] == 0)
					break;

				if (i > 0)
					str_append(str, ", ");
				str_printfa(str, "%u", lines[i]);
			}

			if (i == 1 && size > 0 &&
			    ((const char *)data)[size-1] == '\n')
				size--;
			if (size > 0)
				str_printfa(str, ": %.*s", (int)size, (const char *)data);
			break;
		}
		case MAIL_CACHE_FIELD_COUNT:
			i_unreached();
			break;
		}

		printf("%s\n", str_c(str));
	}
	if (ret < 0)
		printf(" - broken cache\n");
}

static const char *flags2str(enum mail_flags flags)
{
	string_t *str;

	str = t_str_new(64);
	str_append_c(str, '(');
	if ((flags & MAIL_SEEN) != 0)
		str_append(str, "Seen ");
	if ((flags & MAIL_ANSWERED) != 0)
		str_append(str, "Answered ");
	if ((flags & MAIL_FLAGGED) != 0)
		str_append(str, "Flagged ");
	if ((flags & MAIL_DELETED) != 0)
		str_append(str, "Deleted ");
	if ((flags & MAIL_DRAFT) != 0)
		str_append(str, "Draft ");
	if (str_len(str) == 1)
		return "";

	str_truncate(str, str_len(str)-1);
	str_append_c(str, ')');
	return str_c(str);
}

static void dump_record(struct mail_index_view *view, unsigned int seq)
{
	struct mail_index *index = mail_index_view_get_index(view);
	const struct mail_index_record *rec;
	const struct mail_index_registered_ext *ext;
	const void *data;
	unsigned int i, ext_count;
	string_t *str;
	bool expunged;

	rec = mail_index_lookup(view, seq);
	printf("RECORD: seq=%u, uid=%u, flags=0x%02x %s\n",
	       seq, rec->uid, rec->flags, flags2str(rec->flags));

	str = t_str_new(256);
	ext = array_get(&index->extensions, &ext_count);
	for (i = 0; i < ext_count; i++) {
		mail_index_lookup_ext(view, seq, i, &data, &expunged);
		if (data == NULL || ext[i].record_size == 0)
			continue;

		str_truncate(str, 0);
		str_printfa(str, " - ext %d %-10s: ", i, ext[i].name);
		if (ext[i].record_size == sizeof(uint16_t) &&
		    ext[i].record_align == sizeof(uint16_t))
			str_printfa(str, "%10u", *((const uint16_t *)data));
		else if (ext[i].record_size == sizeof(uint32_t) &&
			 ext[i].record_align == sizeof(uint32_t))
			str_printfa(str, "%10u", *((const uint32_t *)data));
		else if (ext[i].record_size == sizeof(uint64_t) &&
			 ext[i].record_align == sizeof(uint64_t)) {
			uint64_t value = *((const uint64_t *)data);
			str_printfa(str, "%10"PRIu64, value);
		} else {
			str_append(str, "          ");
		}
		str_printfa(str, " (%s)",
			    binary_to_hex(data, ext[i].record_size));
		printf("%s\n", str_c(str));
		if (strcmp(ext[i].name, "virtual") == 0) {
			const struct virtual_mail_index_record *vrec = data;
			printf("                   : mailbox_id = %u\n", vrec->mailbox_id);
			printf("                   : real_uid   = %u\n", vrec->real_uid);
		} else if (strcmp(ext[i].name, "map") == 0) {
			const struct mdbox_mail_index_map_record *mrec = data;
			printf("                   : file_id = %u\n", mrec->file_id);
			printf("                   : offset  = %u\n", mrec->offset);
			printf("                   : size    = %u\n", mrec->size);
		} else if (strcmp(ext[i].name, "mdbox") == 0) {
			const struct mdbox_mail_index_record *drec = data;
			printf("                   : map_uid   = %u\n", drec->map_uid);
			printf("                   : save_date = %u (%s)\n", drec->save_date, unixdate2str(drec->save_date));
		} else if (strcmp(ext[i].name, "obox") == 0) {
			const struct obox_mail_index_record *orec = data;
			printf("                   : guid = %s\n", guid_128_to_string(orec->guid));
			printf("                   : oid  = %s\n", binary_to_hex(orec->oid, ext[i].record_size - sizeof(orec->guid)));
		} else if (strcmp(ext[i].name, "mobox") == 0) {
			const struct mobox_mail_index_record *orec = data;
			printf("                   : map_uid   = %u\n", orec->map_uid);
			printf("                   : save_date = %u (%s)\n", orec->save_date, unixdate2str(orec->save_date));
		} else if (strcmp(ext[i].name, "mobox-map") == 0) {
			const struct mobox_map_mail_index_record *orec = data;
			printf("                   : offset = %u\n", orec->offset);
			printf("                   : size   = %u\n", orec->size);
			printf("                   : oid    = %s\n", guid_128_to_string(orec->oid));
		} else if (strcmp(ext[i].name, "list") == 0) {
			const struct mailbox_list_index_record *lrec = data;
			printf("                   : name_id      = %u\n", lrec->name_id);
			printf("                   : parent_uid   = %u\n", lrec->parent_uid);
			printf("                   : guid         = %s\n", guid_128_to_string(lrec->guid));
			printf("                   : uid_validity = %u\n", lrec->uid_validity);
		} else if (strcmp(ext[i].name, "msgs") == 0) {
			const struct mailbox_list_index_msgs_record *lrec = data;
			printf("                   : messages = %u\n", lrec->messages);
			printf("                   : unseen   = %u\n", lrec->unseen);
			printf("                   : recent   = %u\n", lrec->recent);
			printf("                   : uidnext  = %u\n", lrec->uidnext);
		} else if (strcmp(ext[i].name, "vsize") == 0 &&
			   ext[i].record_size >= sizeof(struct mailbox_index_vsize)) {
			/* this is "vsize" in dovecot.list.index, not the
			   32bit "vsize" in dovecot.index */
			const struct mailbox_index_vsize *vrec = data;
			printf("                   : vsize         = %"PRIu64"\n", vrec->vsize);
			printf("                   : highest_uid   = %u\n", vrec->highest_uid);
			printf("                   : message_count = %u\n", vrec->message_count);
		}
	}
}

static bool dir_has_index(const char *dir, const char *name)
{
	struct stat st;

	return stat(t_strconcat(dir, "/", name, NULL), &st) == 0 ||
		stat(t_strconcat(dir, "/", name, ".log", NULL), &st) == 0;
}

static struct mail_index *path_open_index(const char *path)
{
	struct stat st;
	const char *p;

	if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
		if (dir_has_index(path, "dovecot.index"))
			return mail_index_alloc(NULL, path, "dovecot.index");
		else if (dir_has_index(path, "dovecot.map.index"))
			return mail_index_alloc(NULL, path, "dovecot.map.index");
		else
			return NULL;
	} else if ((p = strrchr(path, '/')) != NULL)
		return mail_index_alloc(NULL, t_strdup_until(path, p), p + 1);
	else
		return mail_index_alloc(NULL, ".", path);
}

static void cmd_dump_index(int argc ATTR_UNUSED, char *argv[])
{
	struct mail_index *index;
	struct mail_index_view *view;
	struct mail_cache_view *cache_view;
	unsigned int seq, uid = 0;

	index = path_open_index(argv[1]);
	if (index == NULL ||
	    mail_index_open(index, MAIL_INDEX_OPEN_FLAG_READONLY) <= 0)
		i_fatal("Couldn't open index %s", argv[1]);
	if (argv[2] != NULL) {
		if (str_to_uint(argv[2], &uid) < 0)
			i_fatal("Invalid uid number %s", argv[2]);
	}

	view = mail_index_view_open(index);
	cache_view = mail_cache_view_open(index->cache, view);

	if (uid == 0) {
		printf("-- INDEX: %s\n", index->filepath);
		dump_hdr(index);
		dump_extensions(index);
		dump_keywords(index);

		printf("\n-- CACHE: %s\n", index->cache->filepath);
		dump_cache_hdr(index->cache);

		printf("\n-- RECORDS: %u\n", index->map->hdr.messages_count);
	}
	for (seq = 1; seq <= index->map->hdr.messages_count; seq++) {
		if (uid == 0 || mail_index_lookup(view, seq)->uid == uid) {
			T_BEGIN {
				dump_record(view, seq);
				dump_cache(cache_view, seq);
				printf("\n");
			} T_END;
		}
	}
	mail_cache_view_close(&cache_view);
	mail_index_view_close(&view);
	mail_index_close(index);
	mail_index_free(&index);
}

static bool test_dump_index(const char *path)
{
	struct mail_index *index;
	bool ret;

	index = path_open_index(path);
	if (index == NULL)
		return FALSE;

	ret = mail_index_open(index, MAIL_INDEX_OPEN_FLAG_READONLY) > 0;
	if (ret)
		mail_index_close(index);
	mail_index_free(&index);
	return ret;
}

struct doveadm_cmd_dump doveadm_cmd_dump_index = {
	"index",
	test_dump_index,
	cmd_dump_index
};
