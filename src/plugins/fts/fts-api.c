/* Copyright (c) 2006-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hex-binary.h"
#include "mail-index.h"
#include "mail-storage-private.h"
#include "mail-search.h"
#include "../virtual/virtual-storage.h"
#include "fts-api-private.h"

static ARRAY_DEFINE(backends, const struct fts_backend *);

void fts_backend_register(const struct fts_backend *backend)
{
	if (!array_is_created(&backends))
		i_array_init(&backends, 4);
	array_append(&backends, &backend, 1);
}

void fts_backend_unregister(const char *name)
{
	const struct fts_backend *const *be;
	unsigned int i, count;

	be = array_get(&backends, &count);
	for (i = 0; i < count; i++) {
		if (strcmp(be[i]->name, name) == 0) {
			array_delete(&backends, i, 1);
			break;
		}
	}
	if (i == count)
		i_panic("fts_backend_unregister(%s): unknown backend", name);

	if (count == 1)
		array_free(&backends);
}

static const struct fts_backend *
fts_backend_class_lookup(const char *backend_name)
{
	const struct fts_backend *const *be;
	unsigned int i, count;

	if (array_is_created(&backends)) {
		be = array_get(&backends, &count);
		for (i = 0; i < count; i++) {
			if (strcmp(be[i]->name, backend_name) == 0)
				return be[i];
		}
	}
	return NULL;
}

int fts_backend_init(const char *backend_name, struct mail_namespace *ns,
		     const char **error_r, struct fts_backend **backend_r)
{
	const struct fts_backend *be;
	struct fts_backend *backend;

	be = fts_backend_class_lookup(backend_name);
	if (be == NULL) {
		*error_r = "Unknown backend";
		return -1;
	}

	backend = be->v.alloc();
	backend->ns = ns;
	if (backend->v.init(backend, error_r) < 0) {
		i_free(backend);
		return -1;
	}
	*backend_r = backend;
	return 0;
}

void fts_backend_deinit(struct fts_backend **_backend)
{
	struct fts_backend *backend = *_backend;

	*_backend = NULL;
	backend->v.deinit(backend);
}

int fts_backend_get_last_uid(struct fts_backend *backend, struct mailbox *box,
			     uint32_t *last_uid_r)
{
	if (strcmp(box->storage->name, VIRTUAL_STORAGE_NAME) == 0) {
		/* virtual mailboxes themselves don't have any indexes,
		   so catch this call here */
		if (!fts_index_get_last_uid(box, last_uid_r))
			*last_uid_r = 0;
		return 0;
	}

	return backend->v.get_last_uid(backend, box, last_uid_r);
}

bool fts_backend_is_updating(struct fts_backend *backend)
{
	return backend->updating;
}

struct fts_backend_update_context *
fts_backend_update_init(struct fts_backend *backend)
{
	i_assert(!backend->updating);

	backend->updating = TRUE;
	return backend->v.update_init(backend);
}

static void fts_backend_set_cur_mailbox(struct fts_backend_update_context *ctx)
{
	fts_backend_update_unset_build_key(ctx);
	if (ctx->backend_box != ctx->cur_box) {
		ctx->backend->v.update_set_mailbox(ctx, ctx->cur_box);
		ctx->backend_box = ctx->cur_box;
	}
}

int fts_backend_update_deinit(struct fts_backend_update_context **_ctx)
{
	struct fts_backend_update_context *ctx = *_ctx;

	*_ctx = NULL;

	ctx->cur_box = NULL;
	fts_backend_set_cur_mailbox(ctx);

	return ctx->backend->v.update_deinit(ctx);
}

void fts_backend_update_set_mailbox(struct fts_backend_update_context *ctx,
				    struct mailbox *box)
{
	if (ctx->backend_box != NULL && box != ctx->backend_box) {
		/* make sure we don't reference the backend box anymore */
		ctx->backend->v.update_set_mailbox(ctx, NULL);
		ctx->backend_box = NULL;
	}
	ctx->cur_box = box;
}

void fts_backend_update_expunge(struct fts_backend_update_context *ctx,
				uint32_t uid)
{
	fts_backend_set_cur_mailbox(ctx);
	ctx->backend->v.update_expunge(ctx, uid);
}

bool fts_backend_update_set_build_key(struct fts_backend_update_context *ctx,
				      const struct fts_backend_build_key *key)
{
	fts_backend_set_cur_mailbox(ctx);

	if (!ctx->backend->v.update_set_build_key(ctx, key))
		return FALSE;
	ctx->build_key_open = TRUE;
	return TRUE;
}

void fts_backend_update_unset_build_key(struct fts_backend_update_context *ctx)
{
	if (ctx->build_key_open) {
		ctx->backend->v.update_unset_build_key(ctx);
		ctx->build_key_open = FALSE;
	}
}

int fts_backend_update_build_more(struct fts_backend_update_context *ctx,
				  const unsigned char *data, size_t size)
{
	i_assert(ctx->build_key_open);

	return ctx->backend->v.update_build_more(ctx, data, size);
}

int fts_backend_refresh(struct fts_backend *backend)
{
	return backend->v.refresh(backend);
}

int fts_backend_optimize(struct fts_backend *backend)
{
	return backend->v.optimize == NULL ? 0 :
		backend->v.optimize(backend);
}

static void
fts_merge_maybies(ARRAY_TYPE(seq_range) *dest_maybe,
		  const ARRAY_TYPE(seq_range) *dest_definite,
		  const ARRAY_TYPE(seq_range) *src_maybe,
		  const ARRAY_TYPE(seq_range) *src_definite)
{
	ARRAY_TYPE(seq_range) src_unwanted;
	const struct seq_range *range;
	struct seq_range new_range;
	unsigned int i, count;
	uint32_t seq;

	/* add/leave to dest_maybe if at least one list has maybe,
	   and no lists have none */

	/* create unwanted sequences list from both sources */
	t_array_init(&src_unwanted, 128);
	new_range.seq1 = 0; new_range.seq2 = (uint32_t)-1;
	array_append(&src_unwanted, &new_range, 1);
	seq_range_array_remove_seq_range(&src_unwanted, src_maybe);
	seq_range_array_remove_seq_range(&src_unwanted, src_definite);

	/* drop unwanted uids */
	seq_range_array_remove_seq_range(dest_maybe, &src_unwanted);

	/* add uids that are in dest_definite and src_maybe lists */
	range = array_get(dest_definite, &count);
	for (i = 0; i < count; i++) {
		for (seq = range[i].seq1; seq <= range[i].seq2; seq++) {
			if (seq_range_exists(src_maybe, seq))
				seq_range_array_add(dest_maybe, 0, seq);
		}
	}
}

void fts_filter_uids(ARRAY_TYPE(seq_range) *definite_dest,
		     const ARRAY_TYPE(seq_range) *definite_filter,
		     ARRAY_TYPE(seq_range) *maybe_dest,
		     const ARRAY_TYPE(seq_range) *maybe_filter)
{
	T_BEGIN {
		fts_merge_maybies(maybe_dest, definite_dest,
				  maybe_filter, definite_filter);
	} T_END;
	/* keep only what exists in both lists. the rest is in
	   maybies or not wanted */
	seq_range_array_intersect(definite_dest, definite_filter);
}

bool fts_backend_default_can_lookup(struct fts_backend *backend,
				    const struct mail_search_arg *args)
{
	for (; args != NULL; args = args->next) {
		switch (args->type) {
		case SEARCH_OR:
		case SEARCH_SUB:
		case SEARCH_INTHREAD:
			if (fts_backend_default_can_lookup(backend,
							   args->value.subargs))
				return TRUE;
			break;
		case SEARCH_HEADER:
		case SEARCH_HEADER_ADDRESS:
		case SEARCH_HEADER_COMPRESS_LWSP:
		case SEARCH_BODY:
		case SEARCH_TEXT:
			return TRUE;
		default:
			break;
		}
	}
	return FALSE;
}

bool fts_backend_can_lookup(struct fts_backend *backend,
			    const struct mail_search_arg *args)
{
	return backend->v.can_lookup(backend, args);
}

static int fts_score_map_sort(const struct fts_score_map *m1,
			      const struct fts_score_map *m2)
{
	if (m1->uid < m2->uid)
		return -1;
	if (m1->uid > m2->uid)
		return 1;
	return 0;
}

int fts_backend_lookup(struct fts_backend *backend, struct mailbox *box,
		       struct mail_search_arg *args, bool and_args,
		       struct fts_result *result)
{
	array_clear(&result->definite_uids);
	array_clear(&result->maybe_uids);
	array_clear(&result->scores);

	if (backend->v.lookup(backend, box, args, and_args, result) < 0)
		return -1;

	if (!result->scores_sorted && array_is_created(&result->scores)) {
		array_sort(&result->scores, fts_score_map_sort);
		result->scores_sorted = TRUE;
	}
	return 0;
}

int fts_backend_lookup_multi(struct fts_backend *backend,
			     struct mailbox *const boxes[],
			     struct mail_search_arg *args, bool and_args,
			     struct fts_multi_result *result)
{
	i_assert(boxes[0] != NULL);

	return backend->v.lookup_multi(backend, boxes, args, and_args, result);
}

static bool
fts_index_get_header(struct mailbox *box, struct fts_index_header *hdr_r,
		     uint32_t *ext_id_r)
{
	const void *data;
	size_t data_size;

	*ext_id_r = mail_index_ext_register(box->index, "fts",
					    sizeof(struct fts_index_header),
					    0, 0);
	mail_index_get_header_ext(box->view, *ext_id_r, &data, &data_size);
	if (data_size < sizeof(*hdr_r)) {
		memset(hdr_r, 0, sizeof(*hdr_r));
		return FALSE;
	}

	memcpy(hdr_r, data, data_size);
	return TRUE;
}

bool fts_index_get_last_uid(struct mailbox *box, uint32_t *last_uid_r)
{
	struct fts_index_header hdr;
	uint32_t ext_id;

	if (!fts_index_get_header(box, &hdr, &ext_id)) {
		*last_uid_r = 0;
		return FALSE;
	}

	*last_uid_r = hdr.last_indexed_uid;
	return TRUE;
}

int fts_index_set_last_uid(struct mailbox *box, uint32_t last_uid)
{
	struct mail_index_transaction *trans;
	struct fts_index_header hdr;
	uint32_t ext_id;

	(void)fts_index_get_header(box, &hdr, &ext_id);

	hdr.last_indexed_uid = last_uid;
	trans = mail_index_transaction_begin(box->view, 0);
	mail_index_update_header_ext(trans, ext_id, 0, &hdr, sizeof(hdr));
	return mail_index_transaction_commit(&trans);
}

static const char *indexed_headers[] = {
	"From", "To", "Cc", "Bcc", "Subject"
};

bool fts_header_want_indexed(const char *hdr_name)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(indexed_headers); i++) {
		if (strcasecmp(hdr_name, indexed_headers[i]) == 0)
			return TRUE;
	}
	return FALSE;
}

int fts_mailbox_get_guid(struct mailbox *box, const char **guid_r)
{
	struct mailbox_metadata metadata;
	buffer_t buf;
	unsigned char guid_hex[MAILBOX_GUID_HEX_LENGTH];

	if (mailbox_get_metadata(box, MAILBOX_METADATA_GUID, &metadata) < 0)
		return -1;

	buffer_create_data(&buf, guid_hex, sizeof(guid_hex));
	binary_to_hex_append(&buf, metadata.guid, MAIL_GUID_128_SIZE);
	*guid_r = t_strndup(guid_hex, sizeof(guid_hex));
	return 0;
}
