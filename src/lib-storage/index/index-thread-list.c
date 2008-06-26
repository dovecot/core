/* Copyright (c) 2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "bsearch-insert-pos.h"
#include "istream.h"
#include "ostream.h"
#include "index-storage.h"
#include "index-thread-private.h"

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

struct mail_thread_list_context {
	struct mailbox *box;
	char *path;

	uint32_t reset_counter;
	ARRAY_TYPE(uint32_t) ids;
	ARRAY_TYPE(const_string) msgids;
	uint32_t last_id;
	pool_t msgid_pool;

	unsigned int modified:1;
};

struct mail_thread_list_update_context {
	struct mail_thread_list_context *ctx;
	struct mail_hash_transaction *hash_trans;

	unsigned int refreshed:1;
	unsigned int failed:1;
};

struct mail_thread_list_context *mail_thread_list_init(struct mailbox *box)
{
	struct index_mailbox *ibox = (struct index_mailbox *)box;
	struct mail_thread_list_context *ctx;

	ctx = i_new(struct mail_thread_list_context, 1);
	ctx->box = box;
	ctx->path = i_strdup_printf("%s"MAIL_THREAD_INDEX_SUFFIX".ids",
				    ibox->index->filepath);
	ctx->msgid_pool =
		pool_alloconly_create(MEMPOOL_GROWING"thread msgid pool", 1024);
	i_array_init(&ctx->ids, 32);
	i_array_init(&ctx->msgids, 32);
	return ctx;
}

void mail_thread_list_deinit(struct mail_thread_list_context **_ctx)
{
	struct mail_thread_list_context *ctx = *_ctx;

	*_ctx = NULL;
	array_free(&ctx->ids);
	array_free(&ctx->msgids);
	pool_unref(&ctx->msgid_pool);
	i_free(ctx->path);
	i_free(ctx);
}

struct mail_thread_list_update_context *
mail_thread_list_update_begin(struct mail_thread_list_context *ctx,
			      struct mail_hash_transaction *hash_trans)
{
	struct mail_thread_list_update_context *update_ctx;

	update_ctx = i_new(struct mail_thread_list_update_context, 1);
	update_ctx->ctx = ctx;
	update_ctx->hash_trans = hash_trans;

	if (mail_hash_transaction_is_in_memory(hash_trans))
		update_ctx->refreshed = TRUE;
	return update_ctx;
}

static int uint32_cmp(const void *p1, const void *p2)
{
	const uint32_t *u1 = p1, *u2 = p2;

	return *u1 < *u2 ? -1 : (*u1 > *u2 ? 1 : 0);
}

static int mail_thread_list_read(struct mail_thread_list_context *ctx)
{
	struct istream *input;
	const char *line;
	uint32_t id, prev_id;
	int fd, ret = 0;

	array_clear(&ctx->ids);
	array_clear(&ctx->msgids);
	p_clear(ctx->msgid_pool);

	fd = open(ctx->path, O_RDONLY);
	if (fd == -1) {
		if (errno == ENOENT)
			return 0;
		mail_storage_set_critical(ctx->box->storage,
			"open(%s) failed: %m", ctx->path);
		return -1;
	}
	input = i_stream_create_fd(fd, (size_t)-1, FALSE);
	if ((line = i_stream_read_next_line(input)) == NULL)
		ret = -1;
	else
		ctx->reset_counter = strtoul(line, NULL, 10);

	prev_id = 0;
	while ((line = i_stream_read_next_line(input)) != NULL) {
		for (id = 0; *line >= '0' && *line <= '9'; line++)
			id = id*10 + (*line - '0');
		if (*line != ' ' || id <= prev_id) {
			ret = -1;
			break;
		}
		prev_id = id;
		line++;

		line = p_strdup(ctx->msgid_pool, line);
		array_append(&ctx->ids, &id, 1);
		array_append(&ctx->msgids, &line, 1);
	}
	ctx->last_id = prev_id;
	if (input->stream_errno != 0) {
		errno = input->stream_errno;
		mail_storage_set_critical(ctx->box->storage,
			"read(%s) failed: %m", ctx->path);
		ret = -1;
	} else if (ret < 0) {
		mail_storage_set_critical(ctx->box->storage,
			"Corrupted thread list file %s", ctx->path);
	}
	i_stream_unref(&input);

	if (close(fd) < 0) {
		mail_storage_set_critical(ctx->box->storage,
			"close(%s) failed: %m", ctx->path);
		ret = -1;
	}
	return ret;
}

static int mail_thread_list_refresh(struct mail_thread_list_update_context *ctx)
{
	struct mail_hash_header *hdr;

	if (ctx->refreshed)
		return 0;
	ctx->refreshed = TRUE;

	if (mail_thread_list_read(ctx->ctx) < 0)
		return -1;

	hdr = mail_hash_get_header(ctx->hash_trans);
	if (ctx->ctx->reset_counter != hdr->reset_counter) {
		array_clear(&ctx->ctx->ids);
		array_clear(&ctx->ctx->msgids);
		p_clear(ctx->ctx->msgid_pool);
	}
	return 0;
}

static inline bool
mail_thread_lookup_idx(struct mail_thread_list_update_context *ctx,
		       uint32_t id, unsigned int *idx_r)
{
	const uint32_t *ids;
	unsigned int count;

	ids = array_get(&ctx->ctx->ids, &count);
	return bsearch_insert_pos(&id, ids, I_MIN(count, id), sizeof(*ids),
				  uint32_cmp, idx_r);
}

int mail_thread_list_lookup(struct mail_thread_list_update_context *ctx,
			    uint32_t id, const char **msgid_r)
{
	const char *const *msgid_p;
	unsigned int idx;

	if (!mail_thread_lookup_idx(ctx, id, &idx)) {
		if (mail_thread_list_refresh(ctx) < 0)
			return -1;
		if (!mail_thread_lookup_idx(ctx, id, &idx)) {
			*msgid_r = NULL;
			return 0;
		}
	}

	msgid_p = array_idx(&ctx->ctx->msgids, idx);
	*msgid_r = *msgid_p;
	return 1;
}

uint32_t mail_thread_list_add(struct mail_thread_list_update_context *ctx,
			      const char *msgid)
{
	if (mail_thread_list_refresh(ctx) < 0)
		ctx->failed = TRUE;

	msgid = p_strdup(ctx->ctx->msgid_pool, msgid);
	ctx->ctx->modified = TRUE;
	ctx->ctx->last_id++;
	array_append(&ctx->ctx->ids, &ctx->ctx->last_id, 1);
	array_append(&ctx->ctx->msgids, &msgid, 1);
	return ctx->ctx->last_id;
}

void mail_thread_list_remove(struct mail_thread_list_update_context *ctx,
			     uint32_t id)
{
	unsigned int idx;

	if (mail_thread_list_refresh(ctx) < 0)
		return;

	if (!mail_thread_lookup_idx(ctx, id, &idx)) {
		mail_storage_set_critical(ctx->ctx->box->storage,
					  "%s lost ID %u", ctx->ctx->path, id);
		return;
	}

	ctx->ctx->modified = TRUE;
	array_delete(&ctx->ctx->ids, idx, 1);
	array_delete(&ctx->ctx->msgids, idx, 1);
}

static int mail_thread_list_write(struct mail_thread_list_context *ctx,
				  uint32_t reset_counter)
{
	struct index_mailbox *ibox = (struct index_mailbox *)ctx->box;
	const uint32_t *ids;
	const char *temp_path, *const *msgids;
	unsigned int i, count;
	struct ostream *output;
	string_t *str;
	int fd, ret = 0;

	ids = array_get(&ctx->ids, &count);
	if (count == 0) {
		/* everything deleted */
		if (unlink(ctx->path) < 0 && errno != ENOENT)
			i_error("unlink(%s) failed: %m", ctx->path);
		ctx->modified = FALSE;
		return 0;
	}
	msgids = array_idx(&ctx->msgids, 0);

	/* write all IDs to .tmp file */
	temp_path = t_strconcat(ctx->path, ".tmp", NULL);
	fd = open(temp_path, O_CREAT | O_TRUNC | O_WRONLY, ibox->index->mode);
	if (fd == -1) {
		mail_storage_set_critical(ctx->box->storage,
					  "creat(%s) failed: %m", temp_path);
		return -1;
	}
	str = t_str_new(256);
	output = o_stream_create_fd_file(fd, 0, FALSE);
	str_printfa(str, "%u\n", reset_counter);
	o_stream_send(output, str_data(str), str_len(str));

	for (i = 0; i < count; i++) {
		str_truncate(str, 0);
		str_printfa(str, "%u %s\n", ids[i], msgids[i]);
		o_stream_send(output, str_data(str), str_len(str));
	}
	if (output->last_failed_errno != 0) {
		errno = output->last_failed_errno;
		mail_storage_set_critical(ctx->box->storage,
					  "write(%s) failed: %m", temp_path);
		ret = -1;
	}
	o_stream_unref(&output);
	if (close(fd) < 0) {
		mail_storage_set_critical(ctx->box->storage,
					  "close(%s) failed: %m", temp_path);
		ret = -1;
	}
	if (ret < 0) {
		if (unlink(temp_path) < 0)
			i_error("unlink(%s) failed: %m", temp_path);
		return -1;
	}

	/* finish the write by renaming the file */
	if (rename(temp_path, ctx->path) < 0) {
		mail_storage_set_critical(ctx->box->storage,
			"rename(%s, %s) failed: %m", temp_path, ctx->path);
		return -1;
	}

	ctx->modified = FALSE;
	return 0;
}

int mail_thread_list_commit(struct mail_thread_list_update_context **_ctx)
{
	struct mail_thread_list_update_context *ctx = *_ctx;
	int ret = ctx->failed ? -1 : 0;

	*_ctx = NULL;

	if (ctx->ctx->modified && !ctx->failed &&
	    !mail_hash_transaction_is_in_memory(ctx->hash_trans)) {
		struct mail_hash_header *hdr;

		hdr = mail_hash_get_header(ctx->hash_trans);
		ret = mail_thread_list_write(ctx->ctx, hdr->reset_counter);
	}
	i_free(ctx);
	return ret;
}

void mail_thread_list_rollback(struct mail_thread_list_update_context **_ctx)
{
	struct mail_thread_list_update_context *ctx = *_ctx;

	*_ctx = NULL;
	i_free(ctx);
}
