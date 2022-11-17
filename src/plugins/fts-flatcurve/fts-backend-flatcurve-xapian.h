/* Copyright (c) the Dovecot authors, based on code by Michael Slusarz.
 * See the included COPYING file */

#ifndef FTS_BACKEND_FLATCURVE_XAPIAN_H
#define FTS_BACKEND_FLATCURVE_XAPIAN_H

struct fts_flatcurve_xapian_query_result {
	double score;
	uint32_t uid;
};

struct fts_flatcurve_xapian_db_check {
	int errors;
	unsigned int shards;
};

struct fts_flatcurve_xapian_db_stats {
	int messages;
	unsigned int shards;
	unsigned int version;
};

HASH_TABLE_DEFINE_TYPE(term_counter, char *, void *);

struct fts_flatcurve_xapian_query_iter;

void fts_flatcurve_xapian_init(struct flatcurve_fts_backend *backend);
int fts_flatcurve_xapian_refresh(struct flatcurve_fts_backend *backend,
				 const char **error_r);
int fts_flatcurve_xapian_close(struct flatcurve_fts_backend *backend,
			       const char **error_r);
void fts_flatcurve_xapian_deinit(struct flatcurve_fts_backend *backend);

int fts_flatcurve_xapian_get_last_uid(struct flatcurve_fts_backend *backend,
				      uint32_t *last_uid_r, const char **error_r);
/* Return -1 if DB doesn't exist, 0 if UID doesn't exist, 1 if UID exists */
int fts_flatcurve_xapian_uid_exists(struct flatcurve_fts_backend *backend,
				    uint32_t uid, const char **error_r);
int fts_flatcurve_xapian_expunge(struct flatcurve_fts_backend *backend,
				 uint32_t uid, const char **error_r);
int
fts_flatcurve_xapian_init_msg(struct flatcurve_fts_backend_update_context *ctx,
			      const char **error_r);
int
fts_flatcurve_xapian_index_header(struct flatcurve_fts_backend_update_context *ctx,
				  const unsigned char *data, size_t size,
				  const char **error_r);
int
fts_flatcurve_xapian_index_body(struct flatcurve_fts_backend_update_context *ctx,
				const unsigned char *data, size_t size,
				const char **error_r);
int fts_flatcurve_xapian_optimize_box(struct flatcurve_fts_backend *backend,
				      const char **error_r);
void
fts_flatcurve_xapian_build_query_match_all(struct flatcurve_fts_query *query);
void fts_flatcurve_xapian_build_query(struct flatcurve_fts_query *query);
int fts_flatcurve_xapian_run_query(struct flatcurve_fts_query *query,
				   struct flatcurve_fts_result *r,
				   const char **error_r);
void fts_flatcurve_xapian_destroy_query(struct flatcurve_fts_query *query);
int fts_flatcurve_xapian_delete_index(struct flatcurve_fts_backend *backend,
				      const char **error_r);

struct fts_flatcurve_xapian_query_iter *
fts_flatcurve_xapian_query_iter_init(struct flatcurve_fts_query *query);
bool
fts_flatcurve_xapian_query_iter_next(struct fts_flatcurve_xapian_query_iter *iter,
				     struct fts_flatcurve_xapian_query_result **result_r);
int
fts_flatcurve_xapian_query_iter_deinit(struct fts_flatcurve_xapian_query_iter **_iter,
				       const char **error_r);

int
fts_flatcurve_xapian_mailbox_check(struct flatcurve_fts_backend *backend,
				   struct fts_flatcurve_xapian_db_check *check,
				   const char **error_r);
int
fts_flatcurve_xapian_mailbox_rotate(struct flatcurve_fts_backend *backend,
				    const char **error_r);
int
fts_flatcurve_xapian_mailbox_stats(struct flatcurve_fts_backend *backend,
                                   struct fts_flatcurve_xapian_db_stats *stats,
				   const char **error_r);

int fts_flatcurve_database_locate_dir(const char *path, const char **index_path_r,
				      const char **error_r);
int fts_flatcurve_database_terms(bool headers, const char *path,
				 HASH_TABLE_TYPE(term_counter) *terms,
				 const char **error_r);

void fts_flatcurve_xapian_set_mailbox(struct flatcurve_fts_backend *backend);

const char *fts_flatcurve_xapian_library_version();
#endif
