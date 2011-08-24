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
int fts_expunge_log_append_commit(struct fts_expunge_log_append_ctx **ctx);

int fts_expunge_log_uid_count(struct fts_expunge_log *log,
			      unsigned int *expunges_r);

struct fts_expunge_log_read_ctx *
fts_expunge_log_read_begin(struct fts_expunge_log *log);
const struct fts_expunge_log_read_record *
fts_expunge_log_read_next(struct fts_expunge_log_read_ctx *ctx);
/* Returns 1 if all ok, 0 if there was corruption, -1 if I/O error.
   If end() is called before reading all records, the log isn't unlinked. */
int fts_expunge_log_read_end(struct fts_expunge_log_read_ctx **ctx);

#endif
