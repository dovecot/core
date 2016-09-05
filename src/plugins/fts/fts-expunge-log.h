#ifndef FTS_EXPUNGE_LOG
#define FTS_EXPUNGE_LOG

#include "seq-range-array.h"
#include "guid.h"

struct fts_expunge_log_read_record {
	guid_128_t mailbox_guid;
	ARRAY_TYPE(seq_range) uids;
};

struct fts_expunge_log *fts_expunge_log_init(const char *path);
void fts_expunge_log_deinit(struct fts_expunge_log **log);

struct fts_expunge_log_append_ctx *
fts_expunge_log_append_begin(struct fts_expunge_log *log);
void fts_expunge_log_append_next(struct fts_expunge_log_append_ctx *ctx,
				 const guid_128_t mailbox_guid,
				 uint32_t uid);
void fts_expunge_log_append_range(struct fts_expunge_log_append_ctx *ctx,
				  const guid_128_t mailbox_guid,
				  const struct seq_range *uids);
void fts_expunge_log_append_record(struct fts_expunge_log_append_ctx *ctx,
				   const struct fts_expunge_log_read_record *record);
/* In-memory flattened structures may have records removed from them,
   file-backed ones may not. Non-existence of UIDs is not an error,
   non-existence of mailbox GUID causes an error return of 0. */
int fts_expunge_log_append_remove(struct fts_expunge_log_append_ctx *ctx,
				  const struct fts_expunge_log_read_record *record);
int fts_expunge_log_append_commit(struct fts_expunge_log_append_ctx **ctx);
/* Do not commit non-backed structures, abort them after use. */
int fts_expunge_log_append_abort(struct fts_expunge_log_append_ctx **ctx);

int fts_expunge_log_uid_count(struct fts_expunge_log *log,
			      unsigned int *expunges_r);

struct fts_expunge_log_read_ctx *
fts_expunge_log_read_begin(struct fts_expunge_log *log);
const struct fts_expunge_log_read_record *
fts_expunge_log_read_next(struct fts_expunge_log_read_ctx *ctx);
/* Returns 1 if all ok, 0 if there was corruption, -1 if I/O error.
   If end() is called before reading all records, the log isn't unlinked. */
int fts_expunge_log_read_end(struct fts_expunge_log_read_ctx **ctx);

/* Read an entire log file, and flatten it into one hash of arrays.
   The struct it returns cannot be written, as it has no backing store */
int fts_expunge_log_flatten(const char *path,
			    struct fts_expunge_log_append_ctx **flattened_r);
bool fts_expunge_log_contains(const struct fts_expunge_log_append_ctx *ctx,
			      const guid_128_t mailbox_guid, uint32_t uid);
/* Modify in-place a flattened log. If non-existent mailbox GUIDs are
   encountered, a warning will be logged. */
int fts_expunge_log_subtract(struct fts_expunge_log_append_ctx *from,
			     struct fts_expunge_log *subtract);
/* Write a modified flattened log as a new file. */
int fts_expunge_log_flat_write(const struct fts_expunge_log_append_ctx *flattened,
			       const char *path);
#endif
