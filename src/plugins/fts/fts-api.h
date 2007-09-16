#ifndef FTS_API_H
#define FTS_API_H

struct mail;
struct mailbox;

#include "seq-range-array.h"

enum fts_lookup_flags {
	FTS_LOOKUP_FLAG_HEADERS	= 0x01,
	FTS_LOOKUP_FLAG_BODY	= 0x02
};

struct fts_backend *
fts_backend_init(const char *backend_name, struct mailbox *box);
void fts_backend_deinit(struct fts_backend *backend);

/* Get the last_uid. */
int fts_backend_get_last_uid(struct fts_backend *backend, uint32_t *last_uid_r);

/* Initialize adding new data to the index. last_uid_r is set to the last UID
   that exists in the index. */
struct fts_backend_build_context *
fts_backend_build_init(struct fts_backend *backend, uint32_t *last_uid_r);
/* Add more contents to the index. The data must contain only full valid
   UTF-8 characters, but it doesn't need to be NUL-terminated. size contains
   the data size in bytes, not characters. headers is TRUE if the data contains
   message headers instead of message body. */
int fts_backend_build_more(struct fts_backend_build_context *ctx, uint32_t uid,
			   const unsigned char *data, size_t size,
			   bool headers);
/* Finish adding new data to the index. */
int fts_backend_build_deinit(struct fts_backend_build_context *ctx);

/* Returns TRUE if there exists a build context. */
bool fts_backend_is_building(struct fts_backend *backend);

/* Expunge given mail from the backend. Note that the transaction may still
   fail later. */
void fts_backend_expunge(struct fts_backend *backend, struct mail *mail);
/* Called after transaction has been committed or rollbacked. */
void fts_backend_expunge_finish(struct fts_backend *backend,
				struct mailbox *box, bool committed);

/* Lock/unlock the backend for multiple lookups. Returns 1 if locked, 0 if
   locking timeouted, -1 if error.

   It's not required to call these functions manually, but if you're doing
   multiple lookup/filter operations this avoids multiple lock/unlock calls. */
int fts_backend_lock(struct fts_backend *backend);
void fts_backend_unlock(struct fts_backend *backend);

/* Lookup key from the index and return the found UIDs in result. */
int fts_backend_lookup(struct fts_backend *backend, enum fts_lookup_flags flags,
		       const char *key, ARRAY_TYPE(seq_range) *result);
/* Drop UIDs from the result list for which the key doesn't exist. The idea
   is that with multiple search keywords you first lookup one and then filter
   the rest. */
int fts_backend_filter(struct fts_backend *backend, enum fts_lookup_flags flags,
		       const char *key, ARRAY_TYPE(seq_range) *result);

#endif
