#ifndef FTS_API_H
#define FTS_API_H

struct mail;
struct mailbox;
struct mail_namespace;
struct mail_search_arg;

struct fts_backend;

#include "seq-range-array.h"

enum fts_lookup_flags {
	/* Specifies if the args should be ANDed or ORed together. */
	FTS_LOOKUP_FLAG_AND_ARGS	= 0x01,
	/* Require exact matching for non-fuzzy search args by returning all
	   such matches as maybe_uids instead of definite_uids */
	FTS_LOOKUP_FLAG_NO_AUTO_FUZZY	= 0x02
};

enum fts_backend_build_key_type {
	/* Header */
	FTS_BACKEND_BUILD_KEY_HDR,
	/* MIME part header */
	FTS_BACKEND_BUILD_KEY_MIME_HDR,
	/* MIME body part */
	FTS_BACKEND_BUILD_KEY_BODY_PART,
	/* Binary MIME body part, if backend supports binary data */
	FTS_BACKEND_BUILD_KEY_BODY_PART_BINARY
};

struct fts_backend_build_key {
	uint32_t uid;
	enum fts_backend_build_key_type type;
	struct message_part *part;

	/* for _KEY_HDR: */
	const char *hdr_name;

	/* for _KEY_BODY_PART and _KEY_BODY_PART_BINARY: */

	/* Contains a valid parsed "type/subtype" string. For messages without
	   (valid) Content-Type: header, it's set to "text/plain". */
	const char *body_content_type;
	/* Content-Disposition: header without parsing/validation if it exists,
	   otherwise NULL. */
	const char *body_content_disposition;
};

struct fts_score_map {
	uint32_t uid;
	float score;
};
ARRAY_DEFINE_TYPE(fts_score_map, struct fts_score_map);

struct fts_result {
	struct mailbox *box;

	ARRAY_TYPE(seq_range) definite_uids;
	/* The maybe_uids is useful with backends that can only filter out
	   messages, but can't definitively say if the search matched a
	   message. */
	ARRAY_TYPE(seq_range) maybe_uids;
	ARRAY_TYPE(fts_score_map) scores;
	bool scores_sorted;
};

struct fts_multi_result {
	pool_t pool;
	/* box=NULL-terminated array of mailboxes and matching UIDs,
	   all allocated from the given pool. */
	struct fts_result *box_results;
};

extern struct event_category event_category_fts;

int fts_backend_init(const char *backend_name, struct mail_namespace *ns,
		     const char **error_r, struct fts_backend **backend_r);
void fts_backend_deinit(struct fts_backend **backend);

/* Get the last_uid for the mailbox. */
int fts_backend_get_last_uid(struct fts_backend *backend, struct mailbox *box,
			     uint32_t *last_uid_r);

/* Returns TRUE if there exists an update context. */
bool fts_backend_is_updating(struct fts_backend *backend);

/* Start an index update. */
struct fts_backend_update_context *
fts_backend_update_init(struct fts_backend *backend);
/* Finish an index update. Returns 0 if ok, -1 if some updates failed.
   If updates failed, the index is in unspecified state. */
int fts_backend_update_deinit(struct fts_backend_update_context **ctx);

/* Switch to updating the specified mailbox. box may also be set to NULL to
   make sure the previous mailbox won't tried to be accessed anymore. */
void fts_backend_update_set_mailbox(struct fts_backend_update_context *ctx,
				    struct mailbox *box);
/* Expunge the specified mail. */
void fts_backend_update_expunge(struct fts_backend_update_context *ctx,
				uint32_t uid);

/* Switch to building index for specified key. If backend doesn't want to
   index this key, it can return FALSE and caller will skip to next key. */
bool fts_backend_update_set_build_key(struct fts_backend_update_context *ctx,
				      const struct fts_backend_build_key *key);
/* Make sure that if _build_more() is called, we'll assert-crash. */
void fts_backend_update_unset_build_key(struct fts_backend_update_context *ctx);
/* Add more content to the index for the currently specified build key.
   Non-BODY_PART_BINARY data must contain only full valid UTF-8 characters,
   but it doesn't need to be NUL-terminated. size contains the data size in
   bytes, not characters. This function may be called many times and the data
   block sizes may be small. Backend returns 0 if ok, -1 if build should be
   aborted. */
int fts_backend_update_build_more(struct fts_backend_update_context *ctx,
				  const unsigned char *data, size_t size);

/* Refresh index to make sure we see latest changes from lookups.
   Returns 0 if ok, -1 if error. */
int fts_backend_refresh(struct fts_backend *backend);
/* Go through the entire index and make sure all mails are indexed,
   and delete any extra mails in the index. */
int fts_backend_rescan(struct fts_backend *backend);
/* Optimize the index. This can be a somewhat heavy operation. */
int fts_backend_optimize(struct fts_backend *backend);

/* Returns TRUE if fts_backend_lookup() should even be tried for the
   given args. */
bool fts_backend_can_lookup(struct fts_backend *backend,
			    const struct mail_search_arg *args);
/* Do a FTS lookup for the given search args. Backends can support different
   kinds of search arguments, so match_always=TRUE must be set to all search
   args that were actually used to produce the search results. The other args
   are handled by the regular search code. The backends MUST ignore all args
   that have subargs (SEARCH_OR, SEARCH_SUB), since they are looked up
   separately.

   The arrays in result must be initialized by caller. */
int fts_backend_lookup(struct fts_backend *backend, struct mailbox *box,
		       struct mail_search_arg *args,
		       enum fts_lookup_flags flags,
		       struct fts_result *result);

/* Search from multiple mailboxes. result->pool must be initialized. */
int fts_backend_lookup_multi(struct fts_backend *backend,
			     struct mailbox *const boxes[],
			     struct mail_search_arg *args,
			     enum fts_lookup_flags flags,
			     struct fts_multi_result *result);
/* Called after the lookups are done. The next lookup will be preceded by a
   refresh. */
void fts_backend_lookup_done(struct fts_backend *backend);

#endif
