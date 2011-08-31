#ifndef FTS_BUILD_H
#define FTS_BUILD_H

struct fts_indexer_context;

/* Initialize indexing the given mailbox via indexer service. Returns 1 if
   indexing started, 0 if there was no need to index or -1 if error. */
int fts_indexer_init(struct fts_backend *backend, struct mailbox *box,
		     struct fts_indexer_context **ctx_r);
/* Returns 0 if ok, -1 if error. */
int fts_indexer_deinit(struct fts_indexer_context **ctx);

/* Build more. Returns 1 if finished, 0 if this function needs to be called
   again, -1 if error. */
int fts_indexer_more(struct fts_indexer_context *ctx);

/* Returns fd, which you can either read from or close. */
int fts_indexer_cmd(struct mail_user *user, const char *cmd,
		    const char **path_r);

#endif
