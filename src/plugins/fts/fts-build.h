#ifndef FTS_BUILD_H
#define FTS_BUILD_H

struct fts_storage_build_context;

/* Initialize building. Returns 1 if we need to build (build_ctx set),
   0 if not (build_ctx NULL) or -1 if error. */
int fts_build_init(struct fts_backend *backend, struct mailbox *box,
		   bool precache,
		   struct fts_storage_build_context **build_ctx_r);
/* Returns 0 if ok, -1 if error. */
int fts_build_deinit(struct fts_storage_build_context **ctx);

/* Build more. Returns 1 if finished, 0 if this function needs to be called
   again, -1 if error. */
int fts_build_more(struct fts_storage_build_context *ctx);

#endif
