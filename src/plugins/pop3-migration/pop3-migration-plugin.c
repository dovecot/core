/* Copyright (c) 2007-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "istream-header-filter.h"
#include "str.h"
#include "sha1.h"
#include "message-size.h"
#include "message-header-hash.h"
#include "message-header-parser.h"
#include "mail-cache.h"
#include "mail-namespace.h"
#include "mail-search-build.h"
#include "index-storage.h"
#include "index-mail.h"
#include "pop3-migration-plugin.h"

#define POP3_MIGRATION_CONTEXT(obj) \
	MODULE_CONTEXT(obj, pop3_migration_storage_module)
#define POP3_MIGRATION_CONTEXT_REQUIRE(obj) \
	MODULE_CONTEXT_REQUIRE(obj, pop3_migration_storage_module)
#define POP3_MIGRATION_MAIL_CONTEXT(obj) \
	MODULE_CONTEXT_REQUIRE(obj, pop3_migration_mail_module)

struct msg_map_common {
	/* sha1(header) - set only when needed */
	unsigned char hdr_sha1[SHA1_RESULTLEN];
	bool hdr_sha1_set:1;
};

struct pop3_uidl_map {
	struct msg_map_common common;

	uint32_t pop3_seq;
	uint32_t imap_uid;

	/* UIDL */
	const char *pop3_uidl;
	/* LIST size */
	uoff_t size;
};

struct imap_msg_map {
	struct msg_map_common common;

	uint32_t uid, pop3_seq;
	uoff_t psize;
	const char *pop3_uidl;
};

struct pop3_migration_mail_storage {
	union mail_storage_module_context module_ctx;

	const char *pop3_box_vname;
	ARRAY(struct pop3_uidl_map) pop3_uidl_map;

	bool all_mailboxes:1;
	bool pop3_all_hdr_sha1_set:1;
	bool ignore_missing_uidls:1;
	bool ignore_extra_uidls:1;
	bool skip_size_check:1;
	bool skip_uidl_cache:1;
};

struct pop3_migration_mailbox {
	union mailbox_module_context module_ctx;

	ARRAY(struct imap_msg_map) imap_msg_map;
	unsigned int first_unfound_idx;

	struct mail_cache_field cache_field;

	bool cache_field_registered:1;
	bool uidl_synced:1;
	bool uidl_sync_failed:1;
};

/* NOTE: these headers must be sorted */
static const char *hdr_hash_skip_headers[] = {
	"Content-Length",
	"Return-Path", /* Yahoo IMAP has Return-Path, Yahoo POP3 doesn't */
	"Status",
	"X-IMAP",
	"X-IMAPbase",
	"X-Keywords",
	"X-Message-Flag",
	"X-Status",
	"X-UID",
	"X-UIDL",
	"X-Yahoo-Newman-Property"
};
const char *pop3_migration_plugin_version = DOVECOT_ABI_VERSION;

static MODULE_CONTEXT_DEFINE_INIT(pop3_migration_storage_module,
				  &mail_storage_module_register);
static MODULE_CONTEXT_DEFINE_INIT(pop3_migration_mail_module,
				  &mail_module_register);

static int imap_msg_map_uid_cmp(const struct imap_msg_map *map1,
				const struct imap_msg_map *map2)
{
	if (map1->uid < map2->uid)
		return -1;
	if (map1->uid > map2->uid)
		return 1;
	return 0;
}

static int pop3_uidl_map_pop3_seq_cmp(const struct pop3_uidl_map *map1,
				      const struct pop3_uidl_map *map2)
{
	if (map1->pop3_seq < map2->pop3_seq)
		return -1;
	if (map1->pop3_seq > map2->pop3_seq)
		return 1;
	return 0;
}

static int pop3_uidl_map_uidl_cmp(const struct pop3_uidl_map *map1,
				  const struct pop3_uidl_map *map2)
{
	return strcmp(map1->pop3_uidl, map2->pop3_uidl);
}

static int imap_msg_map_uidl_cmp(const struct imap_msg_map *map1,
				 const struct imap_msg_map *map2)
{
	return null_strcmp(map1->pop3_uidl, map2->pop3_uidl);
}

static int pop3_uidl_map_hdr_cmp(const struct pop3_uidl_map *map1,
				 const struct pop3_uidl_map *map2)
{
	return memcmp(map1->common.hdr_sha1, map2->common.hdr_sha1,
		      sizeof(map1->common.hdr_sha1));
}

static int imap_msg_map_hdr_cmp(const struct imap_msg_map *map1,
				const struct imap_msg_map *map2)
{
	return memcmp(map1->common.hdr_sha1, map2->common.hdr_sha1,
		      sizeof(map1->common.hdr_sha1));
}

struct pop3_hdr_context {
	bool have_eoh;
	bool stop;
};

static bool header_name_is_valid(const char *name)
{
	unsigned int i;

	for (i = 0; name[i] != '\0'; i++) {
		if ((uint8_t)name[i] <= 0x20 || name[i] >= 0x7f)
			return FALSE;
	}
	return TRUE;
}

static bool header_value_want_skip(const struct message_header_line *hdr)
{
	for (size_t i = 0; i < hdr->value_len; i++) {
		if (hdr->value[i] != ' ' && hdr->value[i] != '\t')
			return FALSE;
	}
	/* "header: \r\n \r\n" - Zimbra's BODY[HEADER] strips this line away. */
	return TRUE;
}

static void
pop3_header_filter_callback(struct header_filter_istream *input ATTR_UNUSED,
			    struct message_header_line *hdr,
			    bool *matched, struct pop3_hdr_context *ctx)
{
	if (hdr == NULL)
		return;
	if (hdr->eoh) {
		ctx->have_eoh = TRUE;
		if (ctx->stop)
			*matched = TRUE;
	} else {
		if (strspn(hdr->name, "\r") == hdr->name_len) {
			/* CR+CR+LF - some servers stop the header processing
			 here while others don't. To make sure they can be
			 matched correctly we want to stop here entirely. */
			ctx->stop = TRUE;
		} else if (!hdr->continued && hdr->middle_len == 0) {
			/* not a valid "key: value" header -
			   Zimbra's BODY[HEADER] strips this line away. */
			*matched = TRUE;
		} else if (hdr->continued && header_value_want_skip(hdr)) {
			*matched = TRUE;
		}
		if (ctx->stop)
			*matched = TRUE;
		else if (!header_name_is_valid(hdr->name)) {
			/* Yahoo IMAP drops headers with invalid names, while
			   Yahoo POP3 preserves them. Drop them all. */
			*matched = TRUE;
		}
	}
}

int pop3_migration_get_hdr_sha1(uint32_t mail_seq, struct istream *input,
				unsigned char sha1_r[STATIC_ARRAY SHA1_RESULTLEN],
				bool *have_eoh_r)
{
	const unsigned char *data;
	size_t size;
	struct message_header_hash_context hash_ctx;
	struct sha1_ctxt sha1_ctx;
	struct pop3_hdr_context hdr_ctx;

	i_zero(&hdr_ctx);
	/* hide headers that might change or be different in IMAP vs. POP3 */
	input = i_stream_create_header_filter(input, HEADER_FILTER_HIDE_BODY |
				HEADER_FILTER_EXCLUDE | HEADER_FILTER_NO_CR,
				hdr_hash_skip_headers,
				N_ELEMENTS(hdr_hash_skip_headers),
				pop3_header_filter_callback, &hdr_ctx);

	sha1_init(&sha1_ctx);
	i_zero(&hash_ctx);
	while (i_stream_read_more(input, &data, &size) > 0) {
		message_header_hash_more(&hash_ctx, &hash_method_sha1, &sha1_ctx,
					 MESSAGE_HEADER_HASH_MAX_VERSION,
					 data, size);
		i_stream_skip(input, size);
	}
	if (input->stream_errno != 0) {
		i_error("pop3_migration: Failed to read header for msg %u: %s",
			mail_seq, i_stream_get_error(input));
		i_stream_unref(&input);
		return -1;
	}
	sha1_result(&sha1_ctx, sha1_r);
	i_stream_unref(&input);

	*have_eoh_r = hdr_ctx.have_eoh;
	return 0;
}

static unsigned int get_cache_idx(struct mail *mail)
{
	struct pop3_migration_mailbox *mbox = POP3_MIGRATION_CONTEXT_REQUIRE(mail->box);

	if (mbox->cache_field_registered)
		return mbox->cache_field.idx;

	mbox->cache_field.name = "pop3-migration.hdr";
	mbox->cache_field.type = MAIL_CACHE_FIELD_FIXED_SIZE;
	mbox->cache_field.field_size = SHA1_RESULTLEN;
	mail_cache_register_fields(mail->box->cache, &mbox->cache_field, 1);
	mbox->cache_field_registered = TRUE;
	return mbox->cache_field.idx;
}

static int
get_hdr_sha1(struct mail *mail, unsigned char sha1_r[STATIC_ARRAY SHA1_RESULTLEN])
{
	struct istream *input;
	const char *errstr;
	enum mail_error error;
	bool have_eoh;
	int ret;

	if (mail_get_hdr_stream(mail, NULL, &input) < 0) {
		errstr = mailbox_get_last_internal_error(mail->box, &error);
		i_error("pop3_migration: Failed to get header for msg %u: %s",
			mail->seq, errstr);
		return error == MAIL_ERROR_EXPUNGED ? 0 : -1;
	}
	if (pop3_migration_get_hdr_sha1(mail->seq, input, sha1_r, &have_eoh) < 0)
		return -1;
	if (have_eoh) {
		struct index_mail *imail = (struct index_mail *)mail;

		index_mail_cache_add_idx(imail, get_cache_idx(mail),
					 sha1_r, SHA1_RESULTLEN);
		return 1;
	}

	/* The empty "end of headers" line is missing. Either this means that
	   the headers ended unexpectedly (which is ok) or that the remote
	   server is buggy. Some servers have problems with

	   1) header line continuations that contain only whitespace and
	   2) headers that have no ":". The header gets truncated when such
	   line is reached.

	   At least Oracle IMS IMAP FETCH BODY[HEADER] handles 1) by not
	   returning the whitespace line and 2) by returning the line but
	   truncating the rest. POP3 TOP instead returns the entire header.
	   This causes the IMAP and POP3 hashes not to match.

	   If there's LF+CR+CR+LF in the middle of headers, Courier IMAP's
	   FETCH BODY[HEADER] stops after that, but Courier POP3's TOP doesn't.

	   So we'll try to avoid this by falling back to full FETCH BODY[]
	   (and/or RETR) and we'll parse the header ourself from it. This
	   should work around any similar bugs in all IMAP/POP3 servers. */
	if (mail_get_stream_because(mail, NULL, NULL, "pop3-migration", &input) < 0) {
		errstr = mailbox_get_last_internal_error(mail->box, &error);
		i_error("pop3_migration: Failed to get body for msg %u: %s",
			mail->seq, errstr);
		return error == MAIL_ERROR_EXPUNGED ? 0 : -1;
	}
	ret = pop3_migration_get_hdr_sha1(mail->seq, input, sha1_r, &have_eoh);
	if (ret == 0) {
		if (!have_eoh)
			i_warning("pop3_migration: Truncated email with UID %u stored as truncated", mail->uid);
		struct index_mail *imail = (struct index_mail *)mail;
		index_mail_cache_add_idx(imail, get_cache_idx(mail),
					 sha1_r, SHA1_RESULTLEN);
		return 1;
	} else {
		return -1;
	}
}

static bool
get_cached_hdr_sha1(struct mail *mail, buffer_t *cache_buf,
		    unsigned char sha1_r[STATIC_ARRAY SHA1_RESULTLEN])
{
	struct index_mail *imail = (struct index_mail *)mail;

	buffer_set_used_size(cache_buf, 0);
	if (index_mail_cache_lookup_field(imail, cache_buf,
					  get_cache_idx(mail)) > 0 &&
	    cache_buf->used == SHA1_RESULTLEN) {
		memcpy(sha1_r, cache_buf->data, cache_buf->used);
		return TRUE;
	}
	return FALSE;
}

static struct mailbox *pop3_mailbox_alloc(struct mail_storage *storage)
{
	struct pop3_migration_mail_storage *mstorage =
		POP3_MIGRATION_CONTEXT_REQUIRE(storage);
	struct mail_namespace *ns;
	struct mailbox *box;

	ns = mail_namespace_find(storage->user->namespaces,
				 mstorage->pop3_box_vname);
	i_assert(ns != NULL);
	box = mailbox_alloc(ns->list, mstorage->pop3_box_vname,
			    MAILBOX_FLAG_READONLY | MAILBOX_FLAG_POP3_SESSION);
	mailbox_set_reason(box, "pop3_migration");
	return box;
}

static int pop3_map_read(struct mail_storage *storage, struct mailbox *pop3_box)
{
	struct pop3_migration_mail_storage *mstorage =
		POP3_MIGRATION_CONTEXT_REQUIRE(storage);
	struct mailbox_transaction_context *t;
	struct mail_search_args *search_args;
	struct mail_search_context *ctx;
	struct mail *mail;
	struct pop3_uidl_map *map;
	const char *uidl;
	uoff_t size = (uoff_t)-1;
	int ret = 0;

	if (array_is_created(&mstorage->pop3_uidl_map)) {
		/* already read these, just reset the imap_uids */
		array_foreach_modifiable(&mstorage->pop3_uidl_map, map)
			map->imap_uid = 0;
		return 0;
	}
	i_array_init(&mstorage->pop3_uidl_map, 128);

	if (mailbox_sync(pop3_box, 0) < 0) {
		i_error("pop3_migration: Couldn't sync mailbox %s: %s",
			pop3_box->vname, mailbox_get_last_internal_error(pop3_box, NULL));
		return -1;
	}

	t = mailbox_transaction_begin(pop3_box, 0, __func__);
	search_args = mail_search_build_init();
	mail_search_build_add_all(search_args);
	ctx = mailbox_search_init(t, search_args, NULL,
				  mstorage->skip_size_check ? 0 :
				  MAIL_FETCH_PHYSICAL_SIZE, NULL);
	mail_search_args_unref(&search_args);

	while (mailbox_search_next(ctx, &mail)) {
		/* get the size with LIST instead of RETR */
		mail->lookup_abort = MAIL_LOOKUP_ABORT_READ_MAIL;

		if (mstorage->skip_size_check)
			;
		else if (mail_get_physical_size(mail, &size) < 0) {
			i_error("pop3_migration: Failed to get size for msg %u: %s",
				mail->seq,
				mailbox_get_last_internal_error(pop3_box, NULL));
			ret = -1;
			break;
		}
		mail->lookup_abort = MAIL_LOOKUP_ABORT_NEVER;

		if (mail_get_special(mail, MAIL_FETCH_UIDL_BACKEND, &uidl) < 0) {
			i_error("pop3_migration: Failed to get UIDL for msg %u: %s",
				mail->seq,
				mailbox_get_last_internal_error(pop3_box, NULL));
			ret = -1;
			break;
		}
		if (*uidl == '\0') {
			i_warning("pop3_migration: UIDL for msg %u is empty",
				  mail->seq);
			continue;
		}

		map = array_append_space(&mstorage->pop3_uidl_map);
		map->pop3_seq = mail->seq;
		map->pop3_uidl = p_strdup(storage->pool, uidl);
		map->size = size;
	}

	if (mailbox_search_deinit(&ctx) < 0) {
		i_error("pop3_migration: Failed to search all POP3 mails: %s",
			mailbox_get_last_internal_error(pop3_box, NULL));
		ret = -1;
	}
	(void)mailbox_transaction_commit(&t);
	return ret;
}

static void
pop3_map_read_cached_hdr_hashes(struct mailbox_transaction_context *t,
				struct mail_search_args *search_args,
				struct array *msg_map)
{
	struct mail_search_context *ctx;
	struct mail *mail;
	struct msg_map_common *map;
	buffer_t *cache_buf;

	ctx = mailbox_search_init(t, search_args, NULL, 0, NULL);
	cache_buf = t_buffer_create(SHA1_RESULTLEN);

	while (mailbox_search_next(ctx, &mail)) {
		map = array_idx_modifiable_i(msg_map, mail->seq-1);

		if (get_cached_hdr_sha1(mail, cache_buf, map->hdr_sha1))
			map->hdr_sha1_set = TRUE;
	}

	if (mailbox_search_deinit(&ctx) < 0) {
		i_warning("pop3_migration: Failed to search all cached POP3 header hashes: %s - ignoring",
			  mailbox_get_last_internal_error(t->box, NULL));
	}
}

static void map_remove_found_seqs(struct mail_search_arg *search_arg,
				  struct array *msg_map, uint32_t seq1)
{
	const struct msg_map_common *map;
	uint32_t seq, count = array_count_i(msg_map);

	i_assert(search_arg->type == SEARCH_SEQSET);

	for (seq = seq1; seq <= count; seq++) {
		map = array_idx_i(msg_map, seq-1);
		if (map->hdr_sha1_set)
			seq_range_array_remove(&search_arg->value.seqset, seq);
	}
}

static int
map_read_hdr_hashes(struct mailbox *box, struct array *msg_map, uint32_t seq1)
{
        struct mailbox_transaction_context *t;
	struct mail_search_args *search_args;
	struct mail_search_context *ctx;
	struct mail *mail;
	struct msg_map_common *map;
	int ret = 0;

	t = mailbox_transaction_begin(box, 0, __func__);
	/* get all the cached hashes */
	search_args = mail_search_build_init();
	mail_search_build_add_seqset(search_args, seq1, array_count_i(msg_map));
	pop3_map_read_cached_hdr_hashes(t, search_args, msg_map);
	/* read all the non-cached hashes. doing this in two passes allows
	   us to set wanted_fields=MAIL_FETCH_STREAM_HEADER, which allows
	   prefetching to work without downloading all the headers even
	   for mails that already are cached. */
	map_remove_found_seqs(search_args->args, msg_map, seq1);
	ctx = mailbox_search_init(t, search_args, NULL,
				  MAIL_FETCH_STREAM_HEADER, NULL);
	mail_search_args_unref(&search_args);

	while (mailbox_search_next(ctx, &mail)) {
		map = array_idx_modifiable_i(msg_map, mail->seq-1);

		if ((ret = get_hdr_sha1(mail, map->hdr_sha1)) < 0) {
			ret = -1;
			break;
		}
		if (ret > 0)
			map->hdr_sha1_set = TRUE;
	}

	if (mailbox_search_deinit(&ctx) < 0) {
		i_error("pop3_migration: Failed to search all mail headers: %s",
			mailbox_get_last_internal_error(box, NULL));
		ret = -1;
	}
	(void)mailbox_transaction_commit(&t);
	return ret < 0 ? -1 : 0;
}

static int
pop3_map_read_hdr_hashes(struct mail_storage *storage, struct mailbox *pop3_box,
			 unsigned first_seq)
{
	struct pop3_migration_mail_storage *mstorage =
		POP3_MIGRATION_CONTEXT_REQUIRE(storage);

	if (mstorage->pop3_all_hdr_sha1_set)
		return 0;
	if (mstorage->all_mailboxes) {
		/* we may be matching against multiple mailboxes.
		   read all the hashes only once. */
		first_seq = 1;
	}

	if (map_read_hdr_hashes(pop3_box, &mstorage->pop3_uidl_map.arr,
				first_seq) < 0)
		return -1;

	if (first_seq == 1)
		mstorage->pop3_all_hdr_sha1_set = TRUE;
	return 0;
}

static int imap_map_read(struct mailbox *box)
{
	struct pop3_migration_mailbox *mbox = POP3_MIGRATION_CONTEXT_REQUIRE(box);
	struct index_mailbox_context *ibox = INDEX_STORAGE_CONTEXT(box);
	struct pop3_migration_mail_storage *mstorage =
		POP3_MIGRATION_CONTEXT_REQUIRE(box->storage);
	const unsigned int uidl_cache_idx =
		ibox->cache_fields[MAIL_CACHE_POP3_UIDL].idx;
	struct mailbox_status status;
        struct mailbox_transaction_context *t;
	struct mail_search_args *search_args;
	struct mail_search_context *ctx;
	struct mail *mail;
	struct imap_msg_map *map;
	uoff_t psize = (uoff_t)-1;
	string_t *uidl;
	int ret = 0;

	mailbox_get_open_status(box, STATUS_MESSAGES, &status);

	i_assert(!array_is_created(&mbox->imap_msg_map));
	p_array_init(&mbox->imap_msg_map, box->pool, status.messages);

	t = mailbox_transaction_begin(box, 0, __func__);
	search_args = mail_search_build_init();
	mail_search_build_add_all(search_args);
	ctx = mailbox_search_init(t, search_args, NULL,
				  mstorage->skip_size_check ? 0 :
				  MAIL_FETCH_PHYSICAL_SIZE, NULL);
	mail_search_args_unref(&search_args);

	uidl = t_str_new(64);
	while (mailbox_search_next(ctx, &mail)) {
		if (mstorage->skip_size_check)
			;
		else if (mail_get_physical_size(mail, &psize) < 0) {
			i_error("pop3_migration: Failed to get psize for imap uid %u: %s",
				mail->uid,
				mailbox_get_last_internal_error(box, NULL));
			ret = -1;
			break;
		}

		if (!mstorage->skip_uidl_cache) {
			str_truncate(uidl, 0);
			(void)mail_cache_lookup_field(mail->transaction->cache_view,
						      uidl, mail->seq, uidl_cache_idx);
		}

		map = array_append_space(&mbox->imap_msg_map);
		map->uid = mail->uid;
		map->psize = psize;
		map->pop3_uidl = p_strdup_empty(box->pool, str_c(uidl));
	}

	if (mailbox_search_deinit(&ctx) < 0) {
		i_error("pop3_migration: Failed to search all IMAP mails: %s",
			mailbox_get_last_internal_error(box, NULL));
		ret = -1;
	}
	(void)mailbox_transaction_commit(&t);
	return ret;
}

static int imap_map_read_hdr_hashes(struct mailbox *box)
{
	struct pop3_migration_mailbox *mbox = POP3_MIGRATION_CONTEXT_REQUIRE(box);

	return map_read_hdr_hashes(box, &mbox->imap_msg_map.arr,
				   mbox->first_unfound_idx+1);
}

static void pop3_uidl_assign_cached(struct mailbox *box)
{
	struct pop3_migration_mailbox *mbox = POP3_MIGRATION_CONTEXT_REQUIRE(box);
	struct pop3_migration_mail_storage *mstorage =
		POP3_MIGRATION_CONTEXT_REQUIRE(box->storage);
	struct pop3_uidl_map *pop3_map;
	struct imap_msg_map *imap_map;
	unsigned int imap_idx, pop3_idx, pop3_count, imap_count;
	int ret;

	if (mstorage->skip_uidl_cache)
		return;

	array_sort(&mstorage->pop3_uidl_map, pop3_uidl_map_uidl_cmp);
	array_sort(&mbox->imap_msg_map, imap_msg_map_uidl_cmp);

	pop3_map = array_get_modifiable(&mstorage->pop3_uidl_map, &pop3_count);
	imap_map = array_get_modifiable(&mbox->imap_msg_map, &imap_count);

	/* see if we can match the messages using sizes */
	for (imap_idx = pop3_idx = 0; imap_idx < imap_count; imap_idx++) {
		if (imap_map[imap_idx].pop3_uidl == NULL)
			continue;

		ret = 1;
		for (; pop3_idx < pop3_count; pop3_idx++) {
			ret = strcmp(imap_map[imap_idx].pop3_uidl,
				     pop3_map[pop3_idx].pop3_uidl);
			if (ret >= 0)
				break;
		}
		if (ret == 0) {
			imap_map[imap_idx].pop3_seq =
				pop3_map[pop3_idx].pop3_seq;
			pop3_map[pop3_idx].imap_uid = imap_map[imap_idx].uid;
		}
	}
}

static bool pop3_uidl_assign_by_size(struct mailbox *box)
{
	struct pop3_migration_mailbox *mbox = POP3_MIGRATION_CONTEXT_REQUIRE(box);
	struct pop3_migration_mail_storage *mstorage =
		POP3_MIGRATION_CONTEXT_REQUIRE(box->storage);
	struct pop3_uidl_map *pop3_map;
	struct imap_msg_map *imap_map;
	unsigned int i, pop3_count, imap_count, count;
	unsigned int size_match = 0, uidl_match = 0;

	pop3_map = array_get_modifiable(&mstorage->pop3_uidl_map, &pop3_count);
	imap_map = array_get_modifiable(&mbox->imap_msg_map, &imap_count);
	count = I_MIN(pop3_count, imap_count);

	/* see if we can match the messages using sizes */
	for (i = 0; i < count; i++) {
		if (imap_map[i].pop3_uidl != NULL) {
			/* some of the UIDLs were already found cached. */
			if (strcmp(pop3_map[i].pop3_uidl, imap_map[i].pop3_uidl) == 0) {
				uidl_match++;
				continue;
			}
			/* mismatch - can't trust the sizes */
			break;
		}

		if (pop3_map[i].size != imap_map[i].psize ||
		    mstorage->skip_size_check)
			break;
		if (i+1 < count && pop3_map[i].size == pop3_map[i+1].size) {
			/* two messages with same size, don't trust them */
			break;
		}

		size_match++;
		pop3_map[i].imap_uid = imap_map[i].uid;
		imap_map[i].pop3_uidl = pop3_map[i].pop3_uidl;
		imap_map[i].pop3_seq = pop3_map[i].pop3_seq;
	}
	mbox->first_unfound_idx = i;
	e_debug(box->event, "pop3_migration: cached uidls=%u, size matches=%u, total=%u",
		uidl_match, size_match, count);
	return i == count && imap_count == pop3_count;
}

static int
pop3_uidl_assign_by_hdr_hash(struct mailbox *box, struct mailbox *pop3_box)
{
	struct pop3_migration_mail_storage *mstorage =
		POP3_MIGRATION_CONTEXT_REQUIRE(box->storage);
	struct pop3_migration_mailbox *mbox = POP3_MIGRATION_CONTEXT_REQUIRE(box);
	struct pop3_uidl_map *pop3_map;
	struct imap_msg_map *imap_map;
	unsigned int pop3_idx, imap_idx, pop3_count, imap_count;
	unsigned int first_seq, missing_uids_count;
	uint32_t first_missing_idx = 0, first_missing_seq = (uint32_t)-1;
	int ret;

	first_seq = mbox->first_unfound_idx+1;
	if (pop3_map_read_hdr_hashes(box->storage, pop3_box, first_seq) < 0 ||
	    imap_map_read_hdr_hashes(box) < 0)
		return -1;

	array_sort(&mstorage->pop3_uidl_map, pop3_uidl_map_hdr_cmp);
	array_sort(&mbox->imap_msg_map, imap_msg_map_hdr_cmp);

	pop3_map = array_get_modifiable(&mstorage->pop3_uidl_map, &pop3_count);
	imap_map = array_get_modifiable(&mbox->imap_msg_map, &imap_count);

	pop3_idx = imap_idx = 0;
	while (pop3_idx < pop3_count && imap_idx < imap_count) {
		if (!pop3_map[pop3_idx].common.hdr_sha1_set ||
		    pop3_map[pop3_idx].imap_uid != 0) {
			pop3_idx++;
			continue;
		}
		if (!imap_map[imap_idx].common.hdr_sha1_set ||
		    imap_map[imap_idx].pop3_uidl != NULL) {
			imap_idx++;
			continue;
		}
		ret = memcmp(pop3_map[pop3_idx].common.hdr_sha1,
			     imap_map[imap_idx].common.hdr_sha1,
			     sizeof(pop3_map[pop3_idx].common.hdr_sha1));
		if (ret < 0)
			pop3_idx++;
		else if (ret > 0)
			imap_idx++;
		else {
			pop3_map[pop3_idx].imap_uid = imap_map[imap_idx].uid;
			imap_map[imap_idx].pop3_uidl =
				pop3_map[pop3_idx].pop3_uidl;
			imap_map[imap_idx].pop3_seq =
				pop3_map[pop3_idx].pop3_seq;
		}
	}
	missing_uids_count = 0;
	for (pop3_idx = 0; pop3_idx < pop3_count; pop3_idx++) {
		if (pop3_map[pop3_idx].imap_uid != 0) {
			/* matched */
		} else if (!pop3_map[pop3_idx].common.hdr_sha1_set) {
			/* we treated this mail as expunged - ignore */
		} else {
			uint32_t seq = pop3_map[pop3_idx].pop3_seq;
			if (first_missing_seq > seq) {
				first_missing_seq = seq;
				first_missing_idx = pop3_idx;
			}
			missing_uids_count++;
		}
	}
	if (missing_uids_count > 0 && !mstorage->all_mailboxes) {
		string_t *str = t_str_new(128);
		bool all_imap_mails_found = FALSE;

		str_printfa(str, "pop3_migration: %u POP3 messages have no "
			    "matching IMAP messages (first POP3 msg %u UIDL %s)",
			    missing_uids_count, first_missing_seq,
			    pop3_map[first_missing_idx].pop3_uidl);
		if (imap_count + missing_uids_count == pop3_count) {
			str_append(str, " - all IMAP messages were found "
				"(POP3 contains more than IMAP INBOX - you may want to set pop3_migration_all_mailboxes=yes)");
			all_imap_mails_found = TRUE;
		}
		if (all_imap_mails_found && mstorage->ignore_extra_uidls) {
			/* pop3 had more mails than imap. maybe it was just
			   that a new mail was just delivered. */
		} else if (!mstorage->ignore_missing_uidls) {
			str_append(str, " - set pop3_migration_ignore_missing_uidls=yes");
			if (all_imap_mails_found)
				str_append(str, " or pop3_migration_ignore_extra_uidls=yes");
			i_error("%s to continue anyway", str_c(str));
			return -1;
		}
		i_warning("%s", str_c(str));
	} else
		e_debug(box->event, "pop3_migration: %u mails matched by headers", pop3_count);
	array_sort(&mstorage->pop3_uidl_map, pop3_uidl_map_pop3_seq_cmp);
	array_sort(&mbox->imap_msg_map, imap_msg_map_uid_cmp);
	return 0;
}

static void imap_uidls_add_to_cache(struct mailbox *box)
{
	struct pop3_migration_mailbox *mbox = POP3_MIGRATION_CONTEXT_REQUIRE(box);
	struct mailbox_transaction_context *t;
	struct mail *mail;
	struct index_mail *imail;
	struct imap_msg_map *imap_map;
	unsigned int i, count;
	unsigned int field_idx;

	t = mailbox_transaction_begin(box, 0, __func__);
	mail = mail_alloc(t, 0, NULL);
	imail = INDEX_MAIL(mail);
	field_idx = imail->ibox->cache_fields[MAIL_CACHE_POP3_UIDL].idx;

	imap_map = array_get_modifiable(&mbox->imap_msg_map, &count);
	for (i = 0; i < count; i++) {
		if (imap_map[i].pop3_uidl == NULL)
			continue;

		if (!mail_set_uid(mail, imap_map[i].uid))
			i_unreached();
		if (mail_cache_field_can_add(t->cache_trans, mail->seq, field_idx)) {
			index_mail_cache_add_idx(imail, field_idx,
				imap_map[i].pop3_uidl, strlen(imap_map[i].pop3_uidl)+1);
		}
	}
	mail_free(&mail);
	(void)mailbox_transaction_commit(&t);
}

static int pop3_migration_uidl_sync(struct mailbox *box)
{
	struct pop3_migration_mailbox *mbox = POP3_MIGRATION_CONTEXT_REQUIRE(box);
	struct pop3_migration_mail_storage *mstorage =
		POP3_MIGRATION_CONTEXT_REQUIRE(box->storage);
	struct mailbox *pop3_box;

	pop3_box = pop3_mailbox_alloc(box->storage);
	/* the POP3 server isn't connected to yet. handle all IMAP traffic
	   first before connecting, so POP3 server won't disconnect us due to
	   idling. */
	if (imap_map_read(box) < 0 ||
	    pop3_map_read(box->storage, pop3_box) < 0) {
		mailbox_free(&pop3_box);
		return -1;
	}

	pop3_uidl_assign_cached(box);

	array_sort(&mstorage->pop3_uidl_map, pop3_uidl_map_pop3_seq_cmp);
	array_sort(&mbox->imap_msg_map, imap_msg_map_uid_cmp);

	if (!pop3_uidl_assign_by_size(box)) {
		/* everything wasn't assigned, figure out the rest with
		   header hashes */
		if (pop3_uidl_assign_by_hdr_hash(box, pop3_box) < 0) {
			mailbox_free(&pop3_box);
			return -1;
		}
	}

	if (!mstorage->skip_uidl_cache)
		imap_uidls_add_to_cache(box);

	mbox->uidl_synced = TRUE;
	mailbox_free(&pop3_box);
	return 0;
}

static int pop3_migration_uidl_sync_if_needed(struct mailbox *box)
{
	struct pop3_migration_mailbox *mbox = POP3_MIGRATION_CONTEXT_REQUIRE(box);

	if (mbox->uidl_synced)
		return 0;

	if (mbox->uidl_sync_failed ||
	    pop3_migration_uidl_sync(box) < 0) {
		mbox->uidl_sync_failed = TRUE;
		mail_storage_set_error(box->storage, MAIL_ERROR_TEMP,
				       "POP3 UIDLs couldn't be synced");
		return -1;
	}
	return 0;
}

static int
pop3_migration_get_special(struct mail *_mail, enum mail_fetch_field field,
			   const char **value_r)
{
	struct mail_private *mail = (struct mail_private *)_mail;
	union mail_module_context *mmail = POP3_MIGRATION_MAIL_CONTEXT(mail);
	struct pop3_migration_mailbox *mbox = POP3_MIGRATION_CONTEXT_REQUIRE(_mail->box);
	struct imap_msg_map map_key, *map;

	if (field == MAIL_FETCH_UIDL_BACKEND ||
	    field == MAIL_FETCH_POP3_ORDER) {
		if (pop3_migration_uidl_sync_if_needed(_mail->box) < 0)
			return -1;

		i_zero(&map_key);
		map_key.uid = _mail->uid;
		map = array_bsearch(&mbox->imap_msg_map, &map_key,
				    imap_msg_map_uid_cmp);
		if (map != NULL && map->pop3_uidl != NULL) {
			if (field == MAIL_FETCH_UIDL_BACKEND)
				*value_r = map->pop3_uidl;
			else
				*value_r = t_strdup_printf("%u", map->pop3_seq);
			return 0;
		}
		/* not found from POP3 server, fallback to default */
	}
	return mmail->super.get_special(_mail, field, value_r);
}

static void pop3_migration_mail_allocated(struct mail *_mail)
{
	struct pop3_migration_mail_storage *mstorage =
		POP3_MIGRATION_CONTEXT(_mail->box->storage);
	struct mail_private *mail = (struct mail_private *)_mail;
	struct mail_vfuncs *v = mail->vlast;
	union mail_module_context *mmail;
	struct mail_namespace *ns;

	if (mstorage == NULL ||
	    (!mstorage->all_mailboxes && !_mail->box->inbox_user)) {
		/* assigns UIDLs only for INBOX */
		return;
	}

	ns = mail_namespace_find(_mail->box->storage->user->namespaces,
				 mstorage->pop3_box_vname);
	if (ns == mailbox_get_namespace(_mail->box)) {
		/* we're accessing the pop3-migration namespace itself */
		return;
	}

	mmail = p_new(mail->pool, union mail_module_context, 1);
	mmail->super = *v;
	mail->vlast = &mmail->super;

	v->get_special = pop3_migration_get_special;
	MODULE_CONTEXT_SET_SELF(mail, pop3_migration_mail_module, mmail);
}

static struct mail_search_context *
pop3_migration_mailbox_search_init(struct mailbox_transaction_context *t,
				   struct mail_search_args *args,
				   const enum mail_sort_type *sort_program,
				   enum mail_fetch_field wanted_fields,
				   struct mailbox_header_lookup_ctx *wanted_headers)
{
	struct pop3_migration_mailbox *mbox = POP3_MIGRATION_CONTEXT_REQUIRE(t->box);
	struct pop3_migration_mail_storage *mstorage =
		POP3_MIGRATION_CONTEXT_REQUIRE(t->box->storage);

	if ((wanted_fields & (MAIL_FETCH_UIDL_BACKEND |
			      MAIL_FETCH_POP3_ORDER)) != 0 &&
	    (mstorage->all_mailboxes || t->box->inbox_user)) {
		/* Start POP3 UIDL syncing before the search, so we'll do it
		   before we start sending any FETCH BODY[]s to IMAP. It
		   shouldn't matter much, except this works around a bug in
		   Yahoo IMAP where it sometimes breaks its state when doing
		   a FETCH BODY[] followed by FETCH BODY[HEADER].. */
		(void)pop3_migration_uidl_sync_if_needed(t->box);
	}

	return mbox->module_ctx.super.search_init(t, args, sort_program,
						  wanted_fields, wanted_headers);
}

static void pop3_migration_mailbox_allocated(struct mailbox *box)
{
	struct pop3_migration_mail_storage *mstorage =
		POP3_MIGRATION_CONTEXT(box->storage);
	struct mailbox_vfuncs *v = box->vlast;
	struct pop3_migration_mailbox *mbox;

	if (mstorage == NULL)
		return;

	mbox = p_new(box->pool, struct pop3_migration_mailbox, 1);
	mbox->module_ctx.super = *v;
	box->vlast = &mbox->module_ctx.super;

	v->search_init = pop3_migration_mailbox_search_init;

	MODULE_CONTEXT_SET(box, pop3_migration_storage_module, mbox);
}

static void pop3_migration_mail_storage_destroy(struct mail_storage *storage)
{
	struct pop3_migration_mail_storage *mstorage =
		POP3_MIGRATION_CONTEXT_REQUIRE(storage);

	if (array_is_created(&mstorage->pop3_uidl_map))
		array_free(&mstorage->pop3_uidl_map);

	mstorage->module_ctx.super.destroy(storage);
}

static void pop3_migration_mail_storage_created(struct mail_storage *storage)
{
	struct pop3_migration_mail_storage *mstorage;
	struct mail_storage_vfuncs *v = storage->vlast;
	const char *pop3_box_vname;

	pop3_box_vname = mail_user_plugin_getenv(storage->user,
						 "pop3_migration_mailbox");
	if (pop3_box_vname == NULL) {
		e_debug(storage->user->event, "pop3_migration: No pop3_migration_mailbox setting - disabled");
		return;
	}

	mstorage = p_new(storage->pool, struct pop3_migration_mail_storage, 1);
	mstorage->module_ctx.super = *v;
	storage->vlast = &mstorage->module_ctx.super;
	v->destroy = pop3_migration_mail_storage_destroy;

	mstorage->pop3_box_vname = p_strdup(storage->pool, pop3_box_vname);
	mstorage->all_mailboxes =
		mail_user_plugin_getenv_bool(storage->user,
					"pop3_migration_all_mailboxes");
	mstorage->ignore_missing_uidls =
		mail_user_plugin_getenv_bool(storage->user,
			"pop3_migration_ignore_missing_uidls");
	mstorage->ignore_extra_uidls =
		mail_user_plugin_getenv_bool(storage->user,
			"pop3_migration_ignore_extra_uidls");
	mstorage->skip_size_check =
		mail_user_plugin_getenv_bool(storage->user,
			"pop3_migration_skip_size_check");
	mstorage->skip_uidl_cache =
		mail_user_plugin_getenv_bool(storage->user,
			"pop3_migration_skip_uidl_cache");

	MODULE_CONTEXT_SET(storage, pop3_migration_storage_module, mstorage);
}

static struct mail_storage_hooks pop3_migration_mail_storage_hooks = {
	.mail_allocated = pop3_migration_mail_allocated,
	.mailbox_allocated = pop3_migration_mailbox_allocated,
	.mail_storage_created = pop3_migration_mail_storage_created
};

void pop3_migration_plugin_init(struct module *module)
{
	mail_storage_hooks_add(module, &pop3_migration_mail_storage_hooks);
}

void pop3_migration_plugin_deinit(void)
{
	mail_storage_hooks_remove(&pop3_migration_mail_storage_hooks);
}
