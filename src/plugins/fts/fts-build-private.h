#ifndef FTS_BUILD_PRIVATE_H
#define FTS_BUILD_PRIVATE_H

#include "fts-build.h"

struct fts_storage_build_context;

#define FTS_SEARCH_NONBLOCK_COUNT 50

struct fts_storage_build_vfuncs {
	int (*init)(struct fts_backend *backend, struct mailbox *box,
		    struct fts_storage_build_context **build_ctx_r);
	int (*deinit)(struct fts_storage_build_context *ctx);
	int (*more)(struct fts_storage_build_context *ctx);
};

struct fts_storage_build_context {
	struct mailbox *box;
	struct fts_backend_update_context *update_ctx;
	struct fts_storage_build_vfuncs v;

	struct timeval search_start_time, last_notify;
	unsigned int mail_idx, mail_count;

	struct mailbox_transaction_context *trans;
	struct mail_search_context *search_ctx;

	uint32_t uid;
	char *content_type, *content_disposition;
	struct fts_parser *body_parser;

	unsigned int binary_mime_parts:1;
	unsigned int dtcase:1;
	unsigned int notified:1;
	unsigned int failed:1;
};

extern const struct fts_storage_build_vfuncs fts_storage_build_mailbox_vfuncs;
extern const struct fts_storage_build_vfuncs fts_storage_build_virtual_vfuncs;
extern const struct fts_storage_build_vfuncs fts_storage_build_indexer_vfuncs;

int fts_build_mail(struct fts_storage_build_context *ctx, struct mail *mail);

#endif
