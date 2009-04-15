#ifndef FTS_STORAGE_H
#define FTS_STORAGE_H

struct fts_mailbox {
	union mailbox_module_context module_ctx;
	struct fts_backend *backend_substr;
	struct fts_backend *backend_fast;

	unsigned int last_messages_count, last_uidnext;

	const char *env;
	unsigned int virtual:1;
	unsigned int backend_set:1;
};

struct fts_orig_mailboxes {
	const char *name;
	struct mail_namespace *ns;
	struct mailbox *box;
};

struct fts_search_virtual_context {
	pool_t pool;

	struct mailbox_transaction_context *trans;
	ARRAY_DEFINE(orig_mailboxes, struct fts_orig_mailboxes);
	ARRAY_TYPE(fts_backend_uid_map) last_uids;

	unsigned int boxi, uidi;
};

struct fts_search_context {
	union mail_search_module_context module_ctx;

	struct fts_mailbox *fbox;
	struct mailbox_transaction_context *t;
	struct mail_search_args *args;
	struct mail_search_arg *best_arg;

	struct fts_backend_lookup_context *lookup_ctx_substr, *lookup_ctx_fast;
	ARRAY_TYPE(seq_range) definite_seqs, maybe_seqs;
	ARRAY_TYPE(fts_score_map) score_map;
	unsigned int definite_idx, maybe_idx;
	uint32_t first_nonindexed_seq;

	struct fts_backend *build_backend;
	struct fts_storage_build_context *build_ctx;
	struct fts_search_virtual_context virtual_ctx;

	unsigned int build_initialized:1;
	unsigned int seqs_set:1;
};

/* Figure out if we want to use full text search indexes and update
   backends in fctx accordingly. */
void fts_search_analyze(struct fts_search_context *fctx);
/* Perform the actual index lookup and update definite_uids and maybe_uids. */
void fts_search_lookup(struct fts_search_context *fctx);

#endif
