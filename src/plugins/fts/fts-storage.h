#ifndef FTS_STORAGE_H
#define FTS_STORAGE_H

#include "mail-storage-private.h"
#include "fts-api.h"

enum fts_enforced {
	FTS_ENFORCED_NO,
	FTS_ENFORCED_YES,
	FTS_ENFORCED_BODY,
};

struct fts_scores {
	int refcount;
	ARRAY_TYPE(fts_score_map) score_map;
};

struct fts_search_level {
	ARRAY_TYPE(seq_range) definite_seqs, maybe_seqs;
	buffer_t *args_matches;
	ARRAY_TYPE(fts_score_map) score_map;
};

HASH_TABLE_DEFINE_TYPE(virtual_last_indexed, const char *, void *);

struct fts_search_context {
	union mail_search_module_context module_ctx;

	struct fts_backend *backend;
	struct mailbox *box;
	struct mailbox_transaction_context *t;
	struct mail_search_args *args;
	enum fts_lookup_flags flags;
	enum fts_enforced enforced;

	pool_t result_pool;
	ARRAY(struct fts_search_level) levels;
	buffer_t *orig_matches;

	uint32_t first_unindexed_seq;
	uint32_t next_unindexed_seq;
	HASH_TABLE_TYPE(virtual_last_indexed) last_indexed_virtual_uids;

	/* final scores, combined from all levels */
	struct fts_scores *scores;

	struct fts_indexer_context *indexer_ctx;
	struct fts_search_state *search_state;

	bool virtual_mailbox:1;
	bool fts_lookup_success:1;
	bool indexing_timed_out:1;
	bool virtual_seen_unindexed_gaps:1;
};

/* Figure out if we want to use full text search indexes and update
   backends in fctx accordingly. */
void fts_search_analyze(struct fts_search_context *fctx);
/* Perform the actual index lookup and update definite_uids and maybe_uids. */
void fts_search_lookup(struct fts_search_context *fctx);
/* Returns 1 if everything is already indexed, 0 if not, -1 on error. */
int fts_search_get_first_missing_uid(struct fts_backend *backend,
				     struct mailbox *box,
				     uint32_t *last_indexed_uid_r);
/* Returns FTS backend for the given mailbox (assumes it has one). */
struct fts_backend *fts_mailbox_backend(struct mailbox *box);
/* Returns FTS backend for the given mailbox list, or NULL if it has none. */
struct fts_backend *fts_list_backend(struct mailbox_list *list);

void fts_mail_allocated(struct mail *mail);
void fts_mail_namespaces_added(struct mail_namespace *ns);
void fts_mailbox_allocated(struct mailbox *box);
void fts_mailbox_list_created(struct mailbox_list *list);
#endif
