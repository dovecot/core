/* Copyright (c) 2006-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hex-binary.h"
#include "mail-index.h"
#include "mail-namespace.h"
#include "mail-storage-private.h"
#include "mailbox-list-iter.h"
#include "mail-search.h"
#include "fts-api-private.h"

static ARRAY(const struct fts_backend *) backends;

void fts_backend_register(const struct fts_backend *backend)
{
	if (!array_is_created(&backends))
		i_array_init(&backends, 4);
	array_push_back(&backends, &backend);
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
	struct fts_index_header hdr;

	if (box->virtual_vfuncs != NULL) {
		/* virtual mailboxes themselves don't have any indexes,
		   so catch this call here */
		if (!fts_index_get_header(box, &hdr))
			*last_uid_r = 0;
		else
			*last_uid_r = hdr.last_indexed_uid;
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
	struct fts_backend_update_context *ctx;

	i_assert(!backend->updating);

	backend->updating = TRUE;
	ctx = backend->v.update_init(backend);
	if ((backend->flags & FTS_BACKEND_FLAG_NORMALIZE_INPUT) != 0)
		ctx->normalizer = backend->ns->user->default_normalizer;
	return ctx;
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
	struct fts_backend *backend = ctx->backend;
	int ret;

	*_ctx = NULL;

	ctx->cur_box = NULL;
	fts_backend_set_cur_mailbox(ctx);

	ret = backend->v.update_deinit(ctx);
	backend->updating = FALSE;
	return ret;
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

	i_assert(ctx->cur_box != NULL);

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

int fts_backend_reset_last_uids(struct fts_backend *backend)
{
	struct mailbox_list_iterate_context *iter;
	const struct mailbox_info *info;
	struct mailbox *box;
	int ret = 0;

	iter = mailbox_list_iter_init(backend->ns->list, "*",
				      MAILBOX_LIST_ITER_SKIP_ALIASES |
				      MAILBOX_LIST_ITER_NO_AUTO_BOXES);
	while ((info = mailbox_list_iter_next(iter)) != NULL) {
		if ((info->flags &
		     (MAILBOX_NONEXISTENT | MAILBOX_NOSELECT)) != 0)
			continue;

		box = mailbox_alloc(info->ns->list, info->vname, 0);
		if (mailbox_open(box) == 0) {
			if (fts_index_set_last_uid(box, 0) < 0)
				ret = -1;
		}
		mailbox_free(&box);
	}
	if (mailbox_list_iter_deinit(&iter) < 0)
		ret = -1;
	return ret;
}

int fts_backend_rescan(struct fts_backend *backend)
{
	struct mailbox *box;
	bool virtual_storage;

	box = mailbox_alloc(backend->ns->list, "", 0);
	virtual_storage = box->virtual_vfuncs != NULL;
	mailbox_free(&box);

	if (virtual_storage) {
		/* just reset the last-uids for a virtual storage. */
		return fts_backend_reset_last_uids(backend);
	}

	return backend->v.rescan == NULL ? 0 :
		backend->v.rescan(backend);
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
	array_push_back(&src_unwanted, &new_range);
	seq_range_array_remove_seq_range(&src_unwanted, src_maybe);
	seq_range_array_remove_seq_range(&src_unwanted, src_definite);

	/* drop unwanted uids */
	seq_range_array_remove_seq_range(dest_maybe, &src_unwanted);

	/* add uids that are in dest_definite and src_maybe lists */
	range = array_get(dest_definite, &count);
	for (i = 0; i < count; i++) {
		for (seq = range[i].seq1; seq <= range[i].seq2; seq++) {
			if (seq_range_exists(src_maybe, seq))
				seq_range_array_add(dest_maybe, seq);
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
			if (!args->no_fts)
				return TRUE;
			break;
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
		       struct mail_search_arg *args,
		       enum fts_lookup_flags flags,
		       struct fts_result *result)
{
	array_clear(&result->definite_uids);
	array_clear(&result->maybe_uids);
	array_clear(&result->scores);

	if (backend->v.lookup(backend, box, args, flags, result) < 0)
		return -1;

	if (!result->scores_sorted && array_is_created(&result->scores)) {
		array_sort(&result->scores, fts_score_map_sort);
		result->scores_sorted = TRUE;
	}
	return 0;
}

int fts_backend_lookup_multi(struct fts_backend *backend,
			     struct mailbox *const boxes[],
			     struct mail_search_arg *args,
			     enum fts_lookup_flags flags,
			     struct fts_multi_result *result)
{
	unsigned int i;

	i_assert(boxes[0] != NULL);

	if (backend->v.lookup_multi != NULL) {
		if (backend->v.lookup_multi(backend, boxes, args,
					    flags, result) < 0)
			return -1;
		if (result->box_results == NULL) {
			result->box_results = p_new(result->pool,
						    struct fts_result, 1);
		}
		return 0;
	}

	for (i = 0; boxes[i] != NULL; i++) ;
	result->box_results = p_new(result->pool, struct fts_result, i+1);

	for (i = 0; boxes[i] != NULL; i++) {
		struct fts_result *box_result = &result->box_results[i];

		p_array_init(&box_result->definite_uids, result->pool, 32);
		p_array_init(&box_result->maybe_uids, result->pool, 32);
		p_array_init(&box_result->scores, result->pool, 32);
		if (backend->v.lookup(backend, boxes[i], args,
				      flags, box_result) < 0)
			return -1;
	}
	return 0;
}

void fts_backend_lookup_done(struct fts_backend *backend)
{
	if (backend->v.lookup_done != NULL)
		backend->v.lookup_done(backend);
}

static uint32_t fts_index_get_ext_id(struct mailbox *box)
{
	return mail_index_ext_register(box->index, "fts",
				       sizeof(struct fts_index_header),
				       0, 0);
}

bool fts_index_get_header(struct mailbox *box, struct fts_index_header *hdr_r)
{
	struct mail_index_view *view;
	const void *data;
	size_t data_size;
	bool ret;

	mail_index_refresh(box->index);
	view = mail_index_view_open(box->index);
	mail_index_get_header_ext(view, fts_index_get_ext_id(box),
				  &data, &data_size);
	if (data_size < sizeof(*hdr_r)) {
		i_zero(hdr_r);
		ret = FALSE;
	} else {
		memcpy(hdr_r, data, sizeof(*hdr_r));
		ret = TRUE;
	}
	mail_index_view_close(&view);
	return ret;
}

int fts_index_set_header(struct mailbox *box,
			 const struct fts_index_header *hdr)
{
	struct mail_index_transaction *trans;
	uint32_t ext_id = fts_index_get_ext_id(box);

	trans = mail_index_transaction_begin(box->view, 0);
	mail_index_update_header_ext(trans, ext_id, 0, hdr, sizeof(*hdr));
	return mail_index_transaction_commit(&trans);
}

int fts_index_set_last_uid(struct mailbox *box, uint32_t last_uid)
{
	struct fts_index_header hdr;

	(void)fts_index_get_header(box, &hdr);
	hdr.last_indexed_uid = last_uid;
	return fts_index_set_header(box, &hdr);
}

int fts_index_have_compatible_settings(struct mailbox_list *list,
				       uint32_t checksum)
{
	struct mail_namespace *ns = mailbox_list_get_namespace(list);
	struct mailbox *box;
	struct fts_index_header hdr;
	const char *vname;
	size_t len;
	int ret;

	if ((ns->flags & NAMESPACE_FLAG_INBOX_USER) != 0)
		vname = "INBOX";
	else {
		len = strlen(ns->prefix);
		if (len > 0 && ns->prefix[len-1] == mail_namespace_get_sep(ns))
			len--;
		vname = t_strndup(ns->prefix, len);
	}

	box = mailbox_alloc(list, vname, 0);
	if (mailbox_sync(box, (enum mailbox_sync_flags)0) < 0) {
		i_error("fts: Failed to sync mailbox %s: %s", vname,
			mailbox_get_last_internal_error(box, NULL));
		ret = -1;
	} else {
		ret = fts_index_get_header(box, &hdr) &&
			hdr.settings_checksum == checksum ? 1 : 0;
	}
	mailbox_free(&box);
	return ret;
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

bool fts_header_has_language(const char *hdr_name)
{
	/* FIXME: should email address headers be detected as different
	   languages? That mainly contains people's names.. */
	/*if (message_header_is_address(hdr_name))
		return TRUE;*/

	/* Subject definitely contains language-specific data that can be
	   detected. Comment and Keywords headers also could contain, although
	   just about nobody uses those headers.

	   For now we assume that other headers contain non-language specific
	   data that we don't want to filter in special ways. For example
	   it is good to be able to search for Message-IDs. */
	return strcasecmp(hdr_name, "Subject") == 0 ||
		strcasecmp(hdr_name, "Comments") == 0 ||
		strcasecmp(hdr_name, "Keywords") == 0;
}

int fts_mailbox_get_guid(struct mailbox *box, const char **guid_r)
{
	struct mailbox_metadata metadata;

	if (mailbox_get_metadata(box, MAILBOX_METADATA_GUID, &metadata) < 0)
		return -1;

	*guid_r = guid_128_to_string(metadata.guid);
	return 0;
}
