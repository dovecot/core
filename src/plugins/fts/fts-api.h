#ifndef FTS_API_H
#define FTS_API_H

struct mail;
struct mailbox;
struct fts_backend_build_context;

#include "seq-range-array.h"

enum fts_lookup_flags {
	/* Search within header and/or body.
	   At least one of these must be set. */
	FTS_LOOKUP_FLAG_HEADER	= 0x01,
	FTS_LOOKUP_FLAG_BODY	= 0x02,

	/* The key must NOT be found */
	FTS_LOOKUP_FLAG_INVERT	= 0x04
};

struct fts_backend_uid_map {
	const char *mailbox;
	uint32_t uidvalidity;
	uint32_t uid;
};
ARRAY_DEFINE_TYPE(fts_backend_uid_map, struct fts_backend_uid_map);

struct fts_score_map {
	uint32_t uid;
	float score;
};
ARRAY_DEFINE_TYPE(fts_score_map, struct fts_score_map);

struct fts_backend *
fts_backend_init(const char *backend_name, struct mailbox *box);
void fts_backend_deinit(struct fts_backend **backend);

/* Get the last_uid for the mailbox. */
int fts_backend_get_last_uid(struct fts_backend *backend, uint32_t *last_uid_r);
/* Get last_uids for all mailboxes that might be backend mailboxes for a
   virtual mailbox. The backend can use mailbox_get_virtual_backend_boxes() or
   mailbox_get_virtual_box_patterns() functions to get the list of mailboxes.

   Depending on virtual mailbox configuration, this function may also return
   mailboxes that don't even match the virtual mailbox patterns. The caller
   needs to be able to ignore the unnecessary ones. */
int fts_backend_get_all_last_uids(struct fts_backend *backend, pool_t pool,
				  ARRAY_TYPE(fts_backend_uid_map) *last_uids);

/* Initialize adding new data to the index. last_uid_r is set to the last
   indexed message's IMAP UID */
int fts_backend_build_init(struct fts_backend *backend, uint32_t *last_uid_r,
			   struct fts_backend_build_context **ctx_r);
/* Switch to building index for mail's headers or MIME part headers. */
void fts_backend_build_hdr(struct fts_backend_build_context *ctx, uint32_t uid);
/* Switch to building index for the next body part. If backend doesn't want
   to index this body part (based on content type/disposition check), it can
   return FALSE and caller will skip to next part. The backend must return
   TRUE for all text/xxx and message/rfc822 content types.

   The content_type contains a valid parsed "type/subtype" string. For messages
   without (valid) Content-Type header, the content_type is set to "text/plain".
   The content_disposition is passed without parsing/validation if it exists,
   otherwise it's NULL. */
bool fts_backend_build_body_begin(struct fts_backend_build_context *ctx,
				  uint32_t uid, const char *content_type,
				  const char *content_disposition);
/* Called once when the whole body part has been sent. */
void fts_backend_build_body_end(struct fts_backend_build_context *ctx);
/* Add more content to the index for the currently selected header/body part.
   The data must contain only full valid UTF-8 characters, but it doesn't need
   to be NUL-terminated. size contains the data size in bytes, not characters.
   This function may be called many times and the data block sizes may be
   small. Backend returns 0 if ok, -1 if build should be aborted. */
int fts_backend_build_more(struct fts_backend_build_context *ctx,
			   const unsigned char *data, size_t size);
/* Finish adding new data to the index. */
int fts_backend_build_deinit(struct fts_backend_build_context **ctx);

/* Returns TRUE if there exists a build context. */
bool fts_backend_is_building(struct fts_backend *backend);

/* Expunge given mail from the backend. Note that the transaction may still
   fail later, so backend shouldn't do anything irreversible. */
void fts_backend_expunge(struct fts_backend *backend, struct mail *mail);
/* Called after transaction has been committed or rollbacked. */
void fts_backend_expunge_finish(struct fts_backend *backend,
				struct mailbox *box, bool committed);

/* Refresh database to make sure we see latest changes from lookups.
   Returns 0 if ok, -1 if error. */
int fts_backend_refresh(struct fts_backend *backend);

/* Start building a FTS lookup. */
struct fts_backend_lookup_context *
fts_backend_lookup_init(struct fts_backend *backend);
/* Add a new search key to the lookup. The keys are ANDed together. */
void fts_backend_lookup_add(struct fts_backend_lookup_context *ctx,
			    const char *key, enum fts_lookup_flags flags);
/* Finish the lookup and return found UIDs. The definite_uids are returned
   to client directly, while for maybe_uids Dovecot first verifies (by
   opening and reading the mail) that they really do contain the searched
   keys. The maybe_uids is useful with backends that can only filter out
   messages, but can't definitively say if the search matched a message. */
int fts_backend_lookup_deinit(struct fts_backend_lookup_context **ctx,
			      ARRAY_TYPE(seq_range) *definite_uids,
			      ARRAY_TYPE(seq_range) *maybe_uids,
			      ARRAY_TYPE(fts_score_map) *scores);

#endif
