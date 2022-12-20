/* Copyright (c) the Dovecot authors, based on code by Michael Slusarz.
 * See the included COPYING file */

extern "C" {
#include "lib.h"
#include "file-create-locked.h"
#include "hash.h"
#include "message-header-parser.h"
#include "path-util.h"
#include "mail-storage-private.h"
#include "mail-search.h"
#include "sleep.h"
#include "str.h"
#include "unichar.h"
#include "time-util.h"
#include "fts-backend-flatcurve.h"
#include "fts-backend-flatcurve-xapian.h"
#include <dirent.h>
#include <stdio.h>
};

#pragma GCC diagnostic push
#  ifdef __clang__ // for building xapian's libs from gcc built debian package
#    pragma GCC diagnostic ignored "-W#warnings"
#    pragma GCC diagnostic ignored "-Wunused-command-line-argument"
#  endif
#  include <xapian.h>
#pragma GCC diagnostic pop

#include <algorithm>
#include <sstream>
#include <string>

/* How Xapian DBs work in fts-flatcurve: all data lives in under one
 * per-mailbox directory (FTS_FLATCURVE_LABEL) stored at the root of the
 * mailbox indexes directory.
 *
 * There are two different permanent data types within that library:
 * - "index.###": The actual Xapian DB shards. Combined, this comprises the
 *   FTS data for the mailbox. These shards may be directly written to, but
 *   only when deleting messages - new messages are never stored directly to
 *   this DB. Additionally, these DBs are never directly queried; a dummy
 *   object is used to indirectly query them. These indexes may occasionally
 *   be combined into a single index via optimization processes.
 * - "current.###": Xapian DB that contains the index shard where new messages
 *   are stored. Once this index reaches certain (configurable) limits, a new
 *   shard is created and rotated in as the new current index by creating
 *   a shard with a suffix higher than the previous current DB.
 *
 * Within a session, we create a dummy Xapian::Database object, scan the data
 * directory for all indexes, and add each of them to the dummy object. For
 * queries, we then just need to query the dummy object and Xapian handles
 * everything for us. Writes need to be handled separately, as a
 * WritableDatabase object only supports a single on-disk DB at a time; a DB
 * shard, whether "index" or "current", must be directly written to in order
 * to modify.
 *
 * Data storage: Xapian does not support substring searches by default, so
 * (if substring searching is enabled) we instead need to explicitly store all
 * substrings of the string, up to the point where the substring becomes
 * smaller than min_term_size. Requires libicu in order to correctly handle
 * multi-byte characters. */
#define FLATCURVE_XAPIAN_DB_PREFIX "index."
#define FLATCURVE_XAPIAN_DB_CURRENT_PREFIX "current."

/* These are temporary data types that may appear in the fts directory. They
 * are not intended to perservere between sessions. */
#define FLATCURVE_XAPIAN_DB_OPTIMIZE "optimize"

/* Xapian "recommendations" are that you begin your local prefix identifier
 * with "X" for data that doesn't match with a data type listed as a Xapian
 * "convention". However, this recommendation is for maintaining
 * compatability with the search front-end (Omega) that they provide. We don't
 * care about compatability, so save storage space by using single letter
 * prefixes. Bodytext is stored without prefixes, as it is expected to be the
 * single largest storage pool. */

/* Caution: the code below expects these prefix to be 1-char long */
#define FLATCURVE_XAPIAN_ALL_HEADERS_PREFIX   "A"
#define FLATCURVE_XAPIAN_BOOLEAN_FIELD_PREFIX "B"
#define FLATCURVE_XAPIAN_HEADER_PREFIX        "H"

#define FLATCURVE_XAPIAN_ALL_HEADERS_QP "allhdrs"
#define FLATCURVE_XAPIAN_HEADER_BOOL_QP "hdr_bool"
#define FLATCURVE_XAPIAN_HEADER_QP      "hdr_"
#define FLATCURVE_XAPIAN_BODY_QP        "body"

/* Version database, so that any schema changes can be caught. */
#define FLATCURVE_XAPIAN_DB_KEY_PREFIX "dovecot."
#define FLATCURVE_XAPIAN_DB_VERSION_KEY \
		FLATCURVE_XAPIAN_DB_KEY_PREFIX FTS_FLATCURVE_LABEL
#define FLATCURVE_XAPIAN_DB_VERSION 1

#define FLATCURVE_DBW_LOCK_RETRY_SECS 1
#define FLATCURVE_DBW_LOCK_RETRY_MAX 60
#define FLATCURVE_MANUAL_OPTIMIZE_COMMIT_LIMIT 500

/* Lock: needed to ensure we don't run into race conditions when
 * manipulating current directory. */
#define FLATCURVE_XAPIAN_LOCK_FNAME "flatcurve-lock"
#define FLATCURVE_XAPIAN_LOCK_TIMEOUT_SECS 5

#define ENUM_EMPTY(x) ((enum x) 0)


struct flatcurve_xapian_db_path {
	const char *fname;
	const char *path;
};

enum flatcurve_xapian_db_type {
	FLATCURVE_XAPIAN_DB_TYPE_INDEX,
	FLATCURVE_XAPIAN_DB_TYPE_CURRENT,
	FLATCURVE_XAPIAN_DB_TYPE_OPTIMIZE,
	FLATCURVE_XAPIAN_DB_TYPE_LOCK,
	FLATCURVE_XAPIAN_DB_TYPE_UNKNOWN
};

struct flatcurve_xapian_db {
	Xapian::Database *db;
	Xapian::WritableDatabase *dbw;
	struct flatcurve_xapian_db_path *dbpath;
	unsigned int changes;
	enum flatcurve_xapian_db_type type;
};
HASH_TABLE_DEFINE_TYPE(xapian_db, char *, struct flatcurve_xapian_db *);

struct flatcurve_xapian {
	/* Current database objects. */
	struct flatcurve_xapian_db *dbw_current;
	Xapian::Database *db_read;
	HASH_TABLE_TYPE(xapian_db) dbs;
	unsigned int shards;

	/* Locking for current shard manipulation. */
	struct file_lock *lock;
	const char *lock_path;

	/* Xapian pool: used for per mailbox DB info, so it can be easily
	 * cleared when switching mailboxes. Not for use with long
	 * lived data (e.g. optimize). */
	pool_t pool;

	/* Current document. */
	Xapian::Document *doc;
	uint32_t doc_uid;
	unsigned int doc_updates;
	bool doc_created:1;

	/* List of mailboxes to optimize at shutdown. */
	HASH_TABLE(char *, char *) optimize;

	bool deinit:1;
};

struct flatcurve_fts_query_xapian {
	Xapian::Query *query;
};

struct flatcurve_xapian_db_iter {
	struct flatcurve_fts_backend *backend;
	DIR *dirp;
	char *error;

	/* These are set every time next() is run. */
	struct flatcurve_xapian_db_path *path;
	enum flatcurve_xapian_db_type type;
};

enum flatcurve_xapian_db_opts {
	FLATCURVE_XAPIAN_DB_NOCREATE_CURRENT = BIT(0),
	FLATCURVE_XAPIAN_DB_IGNORE_EMPTY     = BIT(1),
	FLATCURVE_XAPIAN_DB_NOCLOSE_CURRENT  = BIT(2)
};

enum flatcurve_xapian_wdb {
	FLATCURVE_XAPIAN_WDB_CREATE = BIT(0)
};

enum flatcurve_xapian_db_close {
	FLATCURVE_XAPIAN_DB_CLOSE_WDB_COMMIT = BIT(0),
	FLATCURVE_XAPIAN_DB_CLOSE_WDB        = BIT(1),
	FLATCURVE_XAPIAN_DB_CLOSE_DB         = BIT(2),
	FLATCURVE_XAPIAN_DB_CLOSE_ROTATE     = BIT(3),
	FLATCURVE_XAPIAN_DB_CLOSE_MBOX       = BIT(4)
};

/* Externally accessible struct. */
struct fts_flatcurve_xapian_query_iter {
	struct flatcurve_fts_backend *backend;
	struct flatcurve_fts_query *query;
	struct fts_flatcurve_xapian_query_result *result;
	char *error;
	Xapian::Database *db;
	Xapian::Enquire *enquire;
	Xapian::MSetIterator mset_iter;
};

static int
fts_flatcurve_xapian_check_db_version(struct flatcurve_fts_backend *backend,
				      struct flatcurve_xapian_db *xdb,
				      const char **error_r);
static int
fts_flatcurve_xapian_close_db(struct flatcurve_fts_backend *backend,
			      struct flatcurve_xapian_db *xdb,
			      enum flatcurve_xapian_db_close opts,
			      const char **error_r);
static int
fts_flatcurve_xapian_close_dbs(struct flatcurve_fts_backend *backend,
			       enum flatcurve_xapian_db_close opts,
			       const char **error_r);
static int
fts_flatcurve_xapian_db_populate(struct flatcurve_fts_backend *backend,
				 enum flatcurve_xapian_db_opts opts,
				 const char **error_r);

void fts_flatcurve_xapian_init(struct flatcurve_fts_backend *backend)
{
	backend->xapian = p_new(backend->pool, struct flatcurve_xapian, 1);
	backend->xapian->pool =
		pool_alloconly_create(FTS_FLATCURVE_LABEL " xapian", 2048);
	hash_table_create(&backend->xapian->dbs, backend->xapian->pool,
			  4, str_hash, strcmp);
}

void fts_flatcurve_xapian_deinit(struct flatcurve_fts_backend *backend)
{
	struct flatcurve_xapian *x = backend->xapian;
	const char *error;

	x->deinit = TRUE;
	if (hash_table_is_created(x->optimize)) {
		struct hash_iterate_context *iter =
			hash_table_iterate_init(x->optimize);

		void *key, *val;
		while (hash_table_iterate(iter, x->optimize, &key, &val)) {
			str_append(backend->boxname, (const char *)key);
			str_append(backend->db_path, (const char *)val);

			if (fts_flatcurve_xapian_optimize_box(
				backend, &error) < 0)
				e_error(backend->event, "%s", error);
		}

		hash_table_iterate_deinit(&iter);
		hash_table_destroy(&x->optimize);
	}
	if (fts_flatcurve_xapian_close(backend, &error) < 0)
		e_error(backend->event, "Failed to close Xapian: %s", error);
	hash_table_destroy(&x->dbs);
	pool_unref(&x->pool);
	x->deinit = FALSE;
}

static struct flatcurve_xapian_db_path *
fts_flatcurve_xapian_create_db_path(struct flatcurve_fts_backend *backend,
				    const char *fname)
{
	struct flatcurve_xapian_db_path *dbpath;

	dbpath = p_new(backend->xapian->pool,
		       struct flatcurve_xapian_db_path, 1);
	dbpath->fname = p_strdup(backend->xapian->pool, fname);
	dbpath->path = p_strdup_printf(backend->xapian->pool, "%s%s",
				       str_c(backend->db_path), fname);

	return dbpath;
}


/* If dbpath = NULL, delete the entire flatcurve index
 * Returns: 0 if FTS directory doesn't exist, 1 on deletion, -1 on error */
static int
fts_flatcurve_xapian_delete(struct flatcurve_fts_backend *backend,
			    struct flatcurve_xapian_db_path *dbpath,
			    const char **error_r)
{
	const char *path = dbpath == NULL ?
		str_c(backend->db_path) : dbpath->path;
	return fts_backend_flatcurve_delete_dir(path, error_r);
}

static flatcurve_xapian_db_iter *
fts_flatcurve_xapian_db_iter_init(struct flatcurve_fts_backend *backend,
				  enum flatcurve_xapian_db_opts opts)
{
	flatcurve_xapian_db_iter *iter =
		p_new(backend->xapian->pool, struct flatcurve_xapian_db_iter, 1);
	iter->backend = backend;
	iter->dirp = opendir(str_c(backend->db_path));

	if (iter->dirp == NULL &&
	    HAS_NO_BITS(opts, FLATCURVE_XAPIAN_DB_NOCREATE_CURRENT)) {
		iter->error = i_strdup_printf(
			"Cannot open DB (RO); opendir(%s) failed: %m",
			str_c(backend->db_path));
	}
	return iter;
}

static bool
fts_flatcurve_xapian_db_iter_next(struct flatcurve_xapian_db_iter *iter)
{
	if (iter->error != NULL || iter->dirp == NULL)
		return FALSE;

	errno = 0;
	struct dirent *dir = readdir(iter->dirp);
	if (errno != 0) {
		iter->error = i_strdup_printf(
			"readdir(%s) failed: %m",
			str_c(iter->backend->db_path));
		return FALSE;
	}

	if (dir == NULL)
		return FALSE;

	if (strcmp(dir->d_name, ".") == 0 ||
	    strcmp(dir->d_name, "..") == 0)
		return fts_flatcurve_xapian_db_iter_next(iter);

	iter->type = FLATCURVE_XAPIAN_DB_TYPE_UNKNOWN;
	iter->path = fts_flatcurve_xapian_create_db_path(
			iter->backend, dir->d_name);

	struct stat st;
	if (stat(iter->path->path, &st) < 0) {
		iter->error = i_strdup_printf(
			"stat(%s) failed: %m",
			str_c(iter->backend->db_path));
		return FALSE;
	}

	if (str_begins_with(dir->d_name, FLATCURVE_XAPIAN_LOCK_FNAME)) {
		iter->type = FLATCURVE_XAPIAN_DB_TYPE_LOCK;
		return TRUE;
	}

	if (!S_ISDIR(st.st_mode))
		return TRUE;

	if (str_begins_with(dir->d_name, FLATCURVE_XAPIAN_DB_PREFIX))
		iter->type = FLATCURVE_XAPIAN_DB_TYPE_INDEX;
	else if (str_begins_with(dir->d_name, FLATCURVE_XAPIAN_DB_CURRENT_PREFIX))
		iter->type = FLATCURVE_XAPIAN_DB_TYPE_CURRENT;
	else if (strcmp(dir->d_name, FLATCURVE_XAPIAN_DB_OPTIMIZE) == 0)
		iter->type = FLATCURVE_XAPIAN_DB_TYPE_OPTIMIZE;

	return TRUE;
}

/* Returns: 0 on success, -1 on error */
static int
fts_flatcurve_xapian_db_iter_deinit(struct flatcurve_xapian_db_iter **_iter,
				    const char **error_r)
{
	struct flatcurve_xapian_db_iter *iter = *_iter;
	*_iter = NULL;

	if (iter->dirp != NULL && closedir(iter->dirp) < 0) {
		if (iter->error == NULL)
			iter->error = i_strdup_printf(
				"closedir(%s) failed: %m",
				str_c(iter->backend->db_path));
	}

	int ret = 0;
	if (iter->error != NULL) {
		*error_r = t_strdup(iter->error);
		i_free(iter->error);
		ret = -1;
	}

	p_free(iter->backend->xapian->pool, iter);
	return ret;
}

/* Returns: 0 on success, -1 on error */
static int
fts_flatcurve_xapian_write_db_get_do(struct flatcurve_fts_backend *backend,
				     struct flatcurve_xapian_db *xdb,
				     int db_flags, const char **error_r)
{
	if (xdb->dbw != NULL)
		return 0;

	for (unsigned int elapsed = 0;
	     elapsed <= FLATCURVE_DBW_LOCK_RETRY_MAX;
	     elapsed += FLATCURVE_DBW_LOCK_RETRY_SECS) {
		try {
			xdb->dbw = new Xapian::WritableDatabase(
					xdb->dbpath->path, db_flags);
			return 0;
		} catch (Xapian::DatabaseLockError &e) {
			e_debug(backend->event,
				"Waiting for DB (RW, %s) lock",
				xdb->dbpath->fname);
			if (!i_sleep_intr_secs(FLATCURVE_DBW_LOCK_RETRY_SECS)) {
				*error_r = t_strdup_printf(
					"Cannot open DB (RW, %s): "
					"sleep() interrupted by signal",
					xdb->dbpath->fname);
				return -1;
			}
			continue;
		} catch (Xapian::Error &e) {
			*error_r = t_strdup_printf(
				"Cannot open DB (RW, %s): %s",
				xdb->dbpath->fname,
				e.get_description().c_str());
			return -1;
		}
	}
	*error_r = t_strdup_printf(
		"DB (RW, %s) was locked for over %d seconds ",
		xdb->dbpath->fname, FLATCURVE_DBW_LOCK_RETRY_MAX);
	return -1;
}

/* Returns: 0 on success, -1 on error */
static int
fts_flatcurve_xapian_write_db_get(struct flatcurve_fts_backend *backend,
				  struct flatcurve_xapian_db *xdb,
				  enum flatcurve_xapian_wdb wopts,
				  const char **error_r)
{
	if (xdb->dbw != NULL)
		return 0;

	int db_flags = (HAS_ALL_BITS(wopts, FLATCURVE_XAPIAN_WDB_CREATE)
		? Xapian::DB_CREATE_OR_OPEN : Xapian::DB_OPEN) |
		Xapian::DB_NO_SYNC;

	if (fts_flatcurve_xapian_write_db_get_do(
		backend, xdb, db_flags, error_r) < 0)
		return -1;

	if (xdb->type == FLATCURVE_XAPIAN_DB_TYPE_CURRENT &&
	    fts_flatcurve_xapian_check_db_version(backend, xdb, error_r) < 0)
		return -1;

	e_debug(backend->event, "Opened DB (RW, %s) messages=%u version=%u",
		xdb->dbpath->fname, xdb->dbw->get_doccount(),
		FLATCURVE_XAPIAN_DB_VERSION);

	return 0;
}

/* Returns: 0 on success, -1 on error */
static int
fts_flatcurve_xapian_rename_db(struct flatcurve_fts_backend *backend,
			       struct flatcurve_xapian_db_path *path,
			       struct flatcurve_xapian_db_path **newpath_r,
			       const char **error_r)
{
	struct flatcurve_xapian_db_path *newpath = NULL;
	for (unsigned int attempts = 0; attempts < 3; attempts++) {
		std::ostringstream ss;
		std::string new_fname(FLATCURVE_XAPIAN_DB_PREFIX);
		ss << i_rand_limit(8192);
		new_fname += ss.str();

		newpath = fts_flatcurve_xapian_create_db_path(
				backend, new_fname.c_str());

		if (rename(path->path, newpath->path) == 0) {
			if (newpath_r != NULL) *newpath_r = newpath;
			return 0;
		}

		if (errno != ENOTEMPTY && errno != EEXIST)
			break;
		/* Looks like a naming conflict; try again with a different
		 * filename. ss will have fresh randomness, so it most likely
		 * work already at the second attempt.
		 * If after three attempts we still fail, then there's
		 * something else going on and we just give up*/
	}

	*error_r = t_strdup_printf("rename(%s, %s) failed: %m",
				   path->path, newpath->path);
	return -1;
}

static bool
fts_flatcurve_xapian_need_optimize(struct flatcurve_fts_backend *backend)
{
	if (backend->fuser == NULL) return FALSE;
	if (backend->fuser->set.optimize_limit == 0) return FALSE;
	return backend->xapian->shards >= backend->fuser->set.optimize_limit;
}

static void
fts_flatcurve_xapian_optimize_mailbox(struct flatcurve_fts_backend *backend)
{
	struct flatcurve_xapian *x = backend->xapian;

	if (x->deinit || !fts_flatcurve_xapian_need_optimize(backend))
		return;

	if (!hash_table_is_created(x->optimize))
		hash_table_create(&x->optimize, backend->pool, 0, str_hash,
				  strcmp);
	if (hash_table_lookup(x->optimize, str_c(backend->boxname)) == NULL)
		hash_table_insert(x->optimize,
				  p_strdup(backend->pool, str_c(backend->boxname)),
				  p_strdup(backend->pool, str_c(backend->db_path)));
}

/* Returns: 0 on success, -1 on error */
static int
fts_flatcurve_xapian_db_add(struct flatcurve_fts_backend *backend,
			    struct flatcurve_xapian_db_path *dbpath,
			    enum flatcurve_xapian_db_type type,
			    bool open_wdb,
			    struct flatcurve_xapian_db **xdb_r,
			    const char **error_r)
{
	struct flatcurve_xapian *x = backend->xapian;

	if (type != FLATCURVE_XAPIAN_DB_TYPE_INDEX &&
	    type != FLATCURVE_XAPIAN_DB_TYPE_CURRENT) {
		if (xdb_r != NULL) *xdb_r = NULL;
		return 0;
	}

	struct flatcurve_xapian_db *xdb;
	xdb = p_new(x->pool, struct flatcurve_xapian_db, 1);
	xdb->dbpath = dbpath;
	xdb->type = type;

	if (open_wdb && fts_flatcurve_xapian_write_db_get(
		backend, xdb, FLATCURVE_XAPIAN_WDB_CREATE, error_r) < 0)
		return -1;

	hash_table_insert(x->dbs, dbpath->fname, xdb);

	bool failed = FALSE;
	/* If multiple current DBs exist, rename the oldest. */
	if (type == FLATCURVE_XAPIAN_DB_TYPE_CURRENT &&
	    x->dbw_current != NULL) {
		struct flatcurve_xapian_db *db =
			strcmp(dbpath->fname,
			       x->dbw_current->dbpath->fname) > 0 ?
			x->dbw_current : xdb;

		struct flatcurve_xapian_db_path *newpath;
		if (fts_flatcurve_xapian_rename_db(
			backend, db->dbpath, &newpath, error_r) < 0)
			failed = TRUE;
		if (fts_flatcurve_xapian_close_db(
			backend, db, FLATCURVE_XAPIAN_DB_CLOSE_WDB, error_r) < 0)
			failed = TRUE;
		hash_table_remove(x->dbs, db->dbpath->fname);
		hash_table_insert(x->dbs, newpath->fname, db);

		db->dbpath = newpath;
		db->type = FLATCURVE_XAPIAN_DB_TYPE_INDEX;
	}

	if (xdb->type == FLATCURVE_XAPIAN_DB_TYPE_CURRENT)
		x->dbw_current = xdb;

	if (xdb_r != NULL) *xdb_r = xdb;
	return failed ? -1 : 0;
}

/* Returns: lock fd >=0 on success, -1 on error */
static int fts_flatcurve_xapian_lock(struct flatcurve_fts_backend *backend,
				     const char **error_r)
{
	struct flatcurve_xapian *x = backend->xapian;

	if (x->lock_path == NULL)
		x->lock_path = p_strdup_printf(
			x->pool, "%s" FLATCURVE_XAPIAN_LOCK_FNAME,
			str_c(backend->db_path));

	struct file_create_settings set;
	i_zero(&set);
	set.lock_timeout_secs = FLATCURVE_XAPIAN_LOCK_TIMEOUT_SECS;
	set.lock_settings.close_on_free = TRUE;
	set.lock_settings.unlink_on_free = TRUE;
	set.lock_settings.lock_method = backend->parsed_lock_method;

	bool created;
	return file_create_locked(x->lock_path, &set, &x->lock, &created, error_r);
}

static void fts_flatcurve_xapian_unlock(struct flatcurve_fts_backend *backend)
{
	file_lock_free(&backend->xapian->lock);
}

/* Returns: 0 if read DB is null, 1 if database has been addeds, -1 on error */
static int
fts_flatcurve_xapian_db_read_add(struct flatcurve_fts_backend *backend,
				 struct flatcurve_xapian_db *xdb,
				 const char **error_r)
{
	struct flatcurve_xapian *x = backend->xapian;

	if (x->db_read == NULL)
		return 0;

	try {
		xdb->db = new Xapian::Database(xdb->dbpath->path);
	} catch (Xapian::Error &e) {
		*error_r = t_strdup_printf("Cannot open DB (RO; %s); %s",
			xdb->dbpath->fname, e.get_description().c_str());
		return -1;
	}

	if (fts_flatcurve_xapian_check_db_version(backend, xdb, error_r) < 0)
		return -1;

	++x->shards;
	x->db_read->add_database(*(xdb->db));

	fts_flatcurve_xapian_optimize_mailbox(backend);

	return 1;
}

/* Returns: 0 on success, -1 on error */
static int
fts_flatcurve_xapian_create_current(struct flatcurve_fts_backend *backend,
				    enum flatcurve_xapian_db_close copts,
				    const char **error_r)
{
	/* The current shard has filename of the format PREFIX.timestamp. This
	 * ensures that we will catch any current DB renaming done by another
	 * process (reopen() on the DB will fail, causing the entire DB to be
	 * closed/reopened). */

	int ret;
	struct flatcurve_xapian_db *xdb;
	T_BEGIN {
		const char *fname = t_strdup_printf(
			FLATCURVE_XAPIAN_DB_CURRENT_PREFIX "%lu",
			i_microseconds());
		ret = fts_flatcurve_xapian_db_add(backend,
			fts_flatcurve_xapian_create_db_path(backend, fname),
			FLATCURVE_XAPIAN_DB_TYPE_CURRENT, TRUE, &xdb, error_r);
	} T_END;

	if (ret < 0)
		return -1;

	if (xdb == NULL) {
		*error_r = "Could not add db";
		return -1;
	}

	if (fts_flatcurve_xapian_db_read_add(backend, xdb, error_r) < 0)
		return -1;

	if (copts == 0)
		return 0;

	return fts_flatcurve_xapian_close_db(backend, xdb, copts, error_r);
}

/* Returns: 0 on success, -1 on error */
static int
fts_flatcurve_xapian_db_populate(struct flatcurve_fts_backend *backend,
				 enum flatcurve_xapian_db_opts opts,
				 const char **error_r)
{
	struct flatcurve_xapian_db_iter *iter;
	struct flatcurve_xapian *x = backend->xapian;

	bool dbs_exist = hash_table_count(backend->xapian->dbs) > 0;
	bool no_create = HAS_ALL_BITS(opts, FLATCURVE_XAPIAN_DB_NOCREATE_CURRENT);

	if (dbs_exist && (no_create || x->dbw_current != NULL))
		return 0;

	bool lock;
	if (no_create) {
		struct stat st;
		if (stat(str_c(backend->db_path), &st) == 0)
			lock = S_ISDIR(st.st_mode);
		else if (errno == ENOENT)
			lock = FALSE;
		else {
			*error_r = i_strdup_printf(
				"stat(%s) failed: %m",
				str_c(backend->db_path));
			return -1;
		}
	} else {
		if (mailbox_list_mkdir_root(
				backend->backend.ns->list,
				str_c(backend->db_path),
				MAILBOX_LIST_PATH_TYPE_INDEX) < 0) {
			*error_r = i_strdup_printf(
				"Cannot create DB (RW); %s",
				str_c(backend->db_path));
			return -1;
		}
		lock = TRUE;
	}

	if (lock && fts_flatcurve_xapian_lock(backend, error_r) < 0)
		return -1;

	if (!dbs_exist) {
		const char *error, *last_error = NULL;
		iter = fts_flatcurve_xapian_db_iter_init(backend, opts);
		while (fts_flatcurve_xapian_db_iter_next(iter)) {
			if (fts_flatcurve_xapian_db_add(
				backend, iter->path, iter->type,
				FALSE, NULL, &last_error) < 0)
				break;
		}
		if (fts_flatcurve_xapian_db_iter_deinit(&iter, &error) < 0) {
			if (last_error != NULL)
				e_error(backend->event, "%s", error);
			else
				last_error = error;
		}
		if (last_error != NULL) {
			fts_flatcurve_xapian_unlock(backend);
			*error_r = last_error;
			return -1;
		}
	}

	int ret = 0;
	if (!no_create && x->dbw_current == NULL) {
		enum flatcurve_xapian_db_close flags =
			HAS_ALL_BITS(opts, FLATCURVE_XAPIAN_DB_NOCLOSE_CURRENT) ?
				(enum flatcurve_xapian_db_close) 0 :
				FLATCURVE_XAPIAN_DB_CLOSE_WDB;

		ret = fts_flatcurve_xapian_create_current(
				backend, flags, error_r);
	}

	fts_flatcurve_xapian_unlock(backend);
	return ret;
}

/* Returns: 0 if dbw_current == NULL, 1 dbw_current != NULL, -1 on error */
static int
fts_flatcurve_xapian_write_db_current(struct flatcurve_fts_backend *backend,
				      enum flatcurve_xapian_db_opts opts,
				      struct flatcurve_xapian_db **dbw_current_r,
				      const char **error_r)
{
	static const enum flatcurve_xapian_wdb wopts =
		ENUM_EMPTY(flatcurve_xapian_wdb);

	struct flatcurve_xapian *x = backend->xapian;

	if (x->dbw_current != NULL && x->dbw_current->dbw != NULL) {
		if (dbw_current_r != NULL) *dbw_current_r = x->dbw_current;
		return 1;
	}

	opts = (enum flatcurve_xapian_db_opts)
		(opts | FLATCURVE_XAPIAN_DB_NOCLOSE_CURRENT);
	/* dbw_current can be NULL if FLATCURVE_XAPIAN_DB_NOCREATE_CURRENT
	 * is set in opts. */
	if (fts_flatcurve_xapian_db_populate(backend, opts, error_r) < 0)
		return -1;

	if (x->dbw_current == NULL)
		return 0;

	if (fts_flatcurve_xapian_write_db_get(
		backend, x->dbw_current, wopts, error_r) < 0)
		return -1;

	if (dbw_current_r != NULL) *dbw_current_r = x->dbw_current;
	return 1;
}

/* Returns: 0 if DBs table is empty, 1 otherwise, -1 on error */
static int
fts_flatcurve_xapian_read_db(struct flatcurve_fts_backend *backend,
			     enum flatcurve_xapian_db_opts opts,
			     Xapian::Database **db_read_r,
			     const char **error_r)
{
	struct hash_iterate_context *iter;
	void *key, *val;
	struct fts_flatcurve_xapian_db_stats stats;
	struct flatcurve_xapian *x = backend->xapian;
	struct flatcurve_xapian_db *xdb;

	if (x->db_read != NULL) {
		try {
			(void)x->db_read->reopen();
			if (db_read_r != NULL) *db_read_r = x->db_read;
			return 1;
		} catch (Xapian::DatabaseNotFoundError &e) {
			/* This means that the underlying databases have
			 * changed (i.e. DB rotation by another process).
			 * Close all DBs and reopen. */
			if (fts_flatcurve_xapian_close(backend, error_r) < 0)
				return -1;
			return fts_flatcurve_xapian_read_db(
			       backend, opts, db_read_r, error_r);
		}
	}

	if (fts_flatcurve_xapian_db_populate(backend, opts, error_r) < 0)
		return -1;

	if (HAS_ALL_BITS(opts, FLATCURVE_XAPIAN_DB_IGNORE_EMPTY) &&
	    (hash_table_count(x->dbs) == 0))
		return 0;

	x->db_read = new Xapian::Database();

	iter = hash_table_iterate_init(x->dbs);
	while (hash_table_iterate(iter, x->dbs, &key, &val)) {
		xdb = (struct flatcurve_xapian_db *)val;
		if (fts_flatcurve_xapian_db_read_add(
			backend, xdb, error_r) < 0)
			e_error(backend->event, "%s", *error_r);
	}
	hash_table_iterate_deinit(&iter);

	if (fts_flatcurve_xapian_mailbox_stats(backend, &stats, error_r) < 0)
		return -1;

	e_debug(backend->event, "Opened DB (RO) messages=%u version=%u "
		"shards=%u", stats.messages, stats.version, stats.shards);

	if (db_read_r != NULL) *db_read_r = x->db_read;
	return 1;
}

/* Returns: 0 on success, -1 on error */
int
fts_flatcurve_xapian_mailbox_check(struct flatcurve_fts_backend *backend,
				   struct fts_flatcurve_xapian_db_check *check,
				   const char **error_r)
{
	static const enum flatcurve_xapian_db_opts opts =
		(enum flatcurve_xapian_db_opts)
			(FLATCURVE_XAPIAN_DB_NOCREATE_CURRENT |
			 FLATCURVE_XAPIAN_DB_IGNORE_EMPTY);
	struct flatcurve_xapian *x = backend->xapian;

	i_zero(check);

	int ret = fts_flatcurve_xapian_read_db(backend, opts, NULL, error_r);
	if (ret <= 0)
		return ret;

	bool failed = FALSE;
	void *key, *val;
	struct hash_iterate_context *iter = hash_table_iterate_init(x->dbs);
	while (hash_table_iterate(iter, x->dbs, &key, &val)) {
		try {
			struct flatcurve_xapian_db *xdb =
				(struct flatcurve_xapian_db *)val;
			check->errors += Xapian::Database::check(
				xdb->dbpath->path, Xapian::DBCHECK_FIX, NULL);
		} catch (const Xapian::Error &e) {
			const char *error = t_strdup_printf(
				"Check failed; %s",
				e.get_description().c_str());
			if (!failed)
				*error_r = error;
			else
				e_error(backend->event, "%s", error);
			failed = TRUE;
		}
		++check->shards;
	}
	hash_table_iterate_deinit(&iter);
	return failed ? -1 : 0;
}

/* Returns: 0 on success, -1 on error */
int fts_flatcurve_xapian_mailbox_rotate(struct flatcurve_fts_backend *backend,
					const char **error_r)
{
	static const enum flatcurve_xapian_db_opts opts =
		(enum flatcurve_xapian_db_opts)
			(FLATCURVE_XAPIAN_DB_NOCREATE_CURRENT |
			 FLATCURVE_XAPIAN_DB_IGNORE_EMPTY);
	struct flatcurve_xapian_db *xdb;

	int ret = fts_flatcurve_xapian_write_db_current(
		backend, opts, &xdb, error_r);
	if (ret <= 0)
		return ret;

	return fts_flatcurve_xapian_close_db(backend, xdb,
		FLATCURVE_XAPIAN_DB_CLOSE_ROTATE, error_r);
}

/* Returns: 0 if DBs table is empty, 1 otherwise, -1 on error */
int
fts_flatcurve_xapian_mailbox_stats(struct flatcurve_fts_backend *backend,
				   struct fts_flatcurve_xapian_db_stats *stats,
				   const char **error_r)
{
	static const enum flatcurve_xapian_db_opts opts =
		(enum flatcurve_xapian_db_opts)
			(FLATCURVE_XAPIAN_DB_NOCREATE_CURRENT |
			 FLATCURVE_XAPIAN_DB_IGNORE_EMPTY);
	struct flatcurve_xapian *x = backend->xapian;

	if (x->db_read == NULL) {
		int ret = fts_flatcurve_xapian_read_db(backend, opts, NULL, error_r);
		if (ret <= 0) {
			i_zero(stats);
			return ret;
		}
	}
	i_assert(x->db_read != NULL);
	stats->messages = x->db_read->get_doccount();
	stats->shards = x->shards;
	stats->version = FLATCURVE_XAPIAN_DB_VERSION;
	return 1;
}

/* The input of the doveadm dump command can be any file or dir inside the
   flatcurve index tree. Climb the path tree until finding a directory with
   the expected name

   Returns: 0 on success, -1 on failure */
static int fts_flatcurve_database_find_dir(const char *path, const char **dir_r,
					   const char **error_r)
{
	/* These don't depend on inputs and are not going to change during
	   execution. No need to recalculate them each time either */
	static const char *const wanted = FTS_FLATCURVE_LABEL;
	static const size_t wanted_len = strlen(wanted);

	/* Resolve symlinks, . and .. , and repeated path separators
	   what remains is a cleaned path, either relative or absolute
	   that is good to parse */
	const char *normalized;
	if (t_realpath(path, &normalized, error_r) < 0)
		return -1;

	/* Scan into the path and match as many times as possible
	   What we are interested in is the most nested match,
	   i.e. the (last) rightmost one.

	   On each successive iteration we simply start from the
	   end of the preceding match, which in worst case exists
	   as the string nul termination.
	*/
	const char *hit_start, *match_start = NULL;
	for (const char *ptr = normalized;; ptr = hit_start + wanted_len) {
		hit_start = strstr(ptr, wanted);
		if (hit_start == NULL) break;

		/* Safe as wanted_len and wanted are de facto compile
		   time constants */
		const char *hit_end = hit_start + wanted_len;
		if (*hit_end != '\0' && *hit_end != '/') continue;

		/* The first condition protects from underruns */
		if (hit_start > normalized && *(hit_start - 1) != '/') continue;

		match_start = hit_start;
	}
	if (match_start == NULL) {
		*error_r = "could not find a valid xapian database directory";
		return -1;
	};

	/* Safe as wanted_len and wanted are de facto compile time constants
	   match_end derives from normalized by increments of wanted_len size */
	const char *match_end = match_start + wanted_len;
	size_t match_size = match_end - normalized;
	const char *index_dir = t_strndup(normalized, match_size);

	/* Caller expects a trailing slash to be in place */
	*dir_r = t_strdup_printf("%s/", index_dir);
	return 0;
}

/* The input of the doveadm dump command can be any file or dir inside the
   flatcurve index tree. Climb the path tree until we find a directory with
   the expected name.

   Once a dir with the expected name has been located, check if there is at
   least one subdir in it whose name starts either with the db-current-prefix
   or with the db-prefix.

   If none of those is found, consider this an invalid path and fail
   Returns: 0 on success, -1 on failure */
int fts_flatcurve_database_locate_dir(const char *arg_path,
				      const char **index_path_r,
				      const char **error_r)
{
	const char* path;

	if (fts_flatcurve_database_find_dir(arg_path, &path, error_r) < 0)
		return -1;

	DIR *dir = opendir(path);
	if (dir == NULL) {
		*error_r = t_strdup_printf("opendir(%s) failed: %m", path);
		return -1;
	}

	bool valid = FALSE;
	do {
		errno = 0;
		struct dirent *entry = readdir(dir);
		if (errno != 0) {
			*error_r = t_strdup_printf("readdir(%s) failed: %m", path);
			if (closedir(dir) < 0)
				i_error("closedir(%s) failed: %m", path);
			return -1;
		}

		if (entry == NULL)
			break;

		valid = (entry->d_type & DT_DIR) != 0 &&
			(str_begins_with(entry->d_name, FLATCURVE_XAPIAN_DB_CURRENT_PREFIX) ||
			 str_begins_with(entry->d_name, FLATCURVE_XAPIAN_DB_PREFIX));
	}
	while (!valid);

	if (closedir(dir) < 0) {
		*error_r = t_strdup_printf("closedir(%s) failed: %m", path);
		return -1;
	}

	if (!valid) {
		*error_r = t_strdup_printf("No xapian databases in %s", path);
		return -1;
	}

	*index_path_r = path;
	return 0;
}

/* Returns: 0 if no DB, 1 if DB as accessed, -1 on error */
static int
fts_flatcurve_database_terms_fetch(bool headers,
				   struct flatcurve_fts_backend *backend,
				   HASH_TABLE_TYPE(term_counter) *terms,
				   const char **error_r)
{
	static const enum flatcurve_xapian_db_opts opts =
		(enum flatcurve_xapian_db_opts)
			(FLATCURVE_XAPIAN_DB_NOCREATE_CURRENT |
			 FLATCURVE_XAPIAN_DB_IGNORE_EMPTY);

	Xapian::Database *db;
	Xapian::TermIterator iter, end;

	const char *prefix = headers ? FLATCURVE_XAPIAN_BOOLEAN_FIELD_PREFIX : "";

	int ret = fts_flatcurve_xapian_read_db(backend, opts, &db, error_r);
	if (ret <= 0)
		return ret;

	for (iter = db->allterms_begin(prefix), end = db->allterms_end(prefix);
		iter != end; ++iter) {

		const std::string &term = *iter;
		const char *key = term.data();

		if (headers) {
			if (*key == *FLATCURVE_XAPIAN_BOOLEAN_FIELD_PREFIX)
				++key;
			else
				continue;
		} else {
			if (*key == *FLATCURVE_XAPIAN_ALL_HEADERS_PREFIX)
				++key;
			else if (*key == *FLATCURVE_XAPIAN_BOOLEAN_FIELD_PREFIX ||
				 *key == *FLATCURVE_XAPIAN_HEADER_PREFIX)
				continue;
		}

		void *k, *v;
		const char *pkey;
		unsigned int counter = iter.get_termfreq();
		if (hash_table_lookup_full(*terms, key, &k, &v)) {
			counter += POINTER_CAST_TO(v, unsigned int);
			pkey = (const char *)k;
		} else {
			pkey = t_strdup(key);
		}
		hash_table_update(*terms, pkey, POINTER_CAST(counter));
	}
	return 1;
}

/* Returns: 0 if no DB, 1 if DB as accessed, -1 on error */
int fts_flatcurve_database_terms(bool headers, const char *path,
				 HASH_TABLE_TYPE(term_counter) *terms,
				 const char **error_r)
{
	struct flatcurve_fts_backend backend;

	i_zero(&backend);
	backend.pool = pool_alloconly_create("doveadm-" FTS_FLATCURVE_LABEL, 1024);
	backend.db_path = str_new_const(backend.pool, path, strlen(path));
	backend.event = event_create(NULL);
	fts_flatcurve_xapian_init(&backend);

	int ret = fts_flatcurve_database_terms_fetch(
		headers, &backend, terms, error_r);

	fts_flatcurve_xapian_deinit(&backend);
	event_unref(&backend.event);
	pool_unref(&backend.pool);

	return ret;
}

void fts_flatcurve_xapian_set_mailbox(struct flatcurve_fts_backend *backend)
{
	event_set_append_log_prefix(backend->event, p_strdup_printf(
		backend->xapian->pool, FTS_FLATCURVE_LABEL "(%s): ",
		str_c(backend->boxname)));
}

/* Returns: 0 on success, -1 on error */
static int
fts_flatcurve_xapian_check_db_version(struct flatcurve_fts_backend *backend,
				      struct flatcurve_xapian_db *xdb,
				      const char **error_r)
{
	static const enum flatcurve_xapian_wdb wopts =
		ENUM_EMPTY(flatcurve_xapian_wdb);

	Xapian::Database *db = (xdb->dbw == NULL) ? xdb->db : xdb->dbw;

	std::string str = db->get_metadata(FLATCURVE_XAPIAN_DB_VERSION_KEY);
	const char* value = str.c_str();
	unsigned int ver = 0;
	if (*value != '\0' && str_to_uint(value, &ver) < 0)
		e_error(backend->event,
			"unexpected Xapian db version '%s' in %s",
			value, str_c(backend->db_path));

	if (ver == FLATCURVE_XAPIAN_DB_VERSION)
		return 0;

	/* If we need to upgrade DB, and this is NOT the write DB, open the
	 * write DB, do the changes there, and reopen the read DB. */
	if (xdb->dbw == NULL) {
		if (fts_flatcurve_xapian_write_db_get(
			backend, xdb, wopts, error_r) < 0)
			return -1;
		if (fts_flatcurve_xapian_close_db(
			backend, xdb, FLATCURVE_XAPIAN_DB_CLOSE_WDB, error_r) < 0)
			return -1;
		(void)xdb->db->reopen();
		return 0;
        }

	/* 0->1: Added DB version. Always implicity update version when we
	 * upgrade (done at end of this function). */
	if (ver == 0) ++ver;
	T_BEGIN {
		xdb->dbw->set_metadata(FLATCURVE_XAPIAN_DB_VERSION_KEY,
				       dec2str(ver));
	} T_END;

	/* Commit the changes now. */
	try {
		xdb->dbw->commit();
		return 0;
	}
	catch(Xapian::Error &e) {
		e_error(backend->event,
			"Xapian::Error on '%s': %s",
			str_c(backend->db_path),
			e.get_description().c_str());
		return -1;
	}
}

/* Requires read DB to have been opened
 * Returns: 0 not found, 1 if found, -1 on error */
static int
fts_flatcurve_xapian_uid_exists_db(struct flatcurve_fts_backend *backend,
				   uint32_t uid,
				   struct flatcurve_xapian_db **xdb_r,
				   const char **error_r)
{
	void *key, *val;
	int ret = 0;
        struct hash_iterate_context *iter =
		hash_table_iterate_init(backend->xapian->dbs);

        while (hash_table_iterate(iter, backend->xapian->dbs, &key, &val)) {
		try {
			struct flatcurve_xapian_db *xdb =
				(struct flatcurve_xapian_db *)val;
			(void)xdb->db->get_document(uid);
			if (xdb_r != NULL) *xdb_r = xdb;
			ret = 1;
			break;
		}
		catch (Xapian::DocNotFoundError &e) {
			continue;
		}
		catch (Xapian::Error &e) {
			*error_r = t_strdup(e.get_description().c_str());
			ret = -1;
			break;
		}
	}
	hash_table_iterate_deinit(&iter);
	return ret;
}

/* Returns: 0 if no DBs, 1 if DB exists, -1 on error */
static int
fts_flatcurve_xapian_write_db_by_uid(struct flatcurve_fts_backend *backend,
				     uint32_t uid,
				     struct flatcurve_xapian_db **xdb_r,
				     const char **error_r)
{
	static const enum flatcurve_xapian_db_opts opts =
		ENUM_EMPTY(flatcurve_xapian_db_opts);
	static const enum flatcurve_xapian_wdb wopts =
		ENUM_EMPTY(flatcurve_xapian_wdb);

	if (fts_flatcurve_xapian_read_db(backend, opts, NULL, error_r) < 0)
		return -1;

	struct flatcurve_xapian_db *xdb;
	int ret = fts_flatcurve_xapian_uid_exists_db(backend, uid, &xdb, error_r);
	if (ret <= 0)
		return ret;

	if (fts_flatcurve_xapian_write_db_get(
		backend, xdb, wopts, error_r) < 0)
		return -1;

	*xdb_r = xdb;
	return 1;
}

/* Returns: 0 on success, -1 on error */
static int
fts_flatcurve_xapian_check_commit_limit(struct flatcurve_fts_backend *backend,
					struct flatcurve_xapian_db *xdb,
					const char **error_r)
{
	struct fts_flatcurve_user *fuser = backend->fuser;
	struct flatcurve_xapian *x = backend->xapian;

	++x->doc_updates;
	++xdb->changes;

	if (xdb->type == FLATCURVE_XAPIAN_DB_TYPE_CURRENT &&
	    fuser->set.rotate_count > 0 &&
	    xdb->dbw->get_doccount() >= fuser->set.rotate_count) {
		return fts_flatcurve_xapian_close_db(
			backend, xdb, FLATCURVE_XAPIAN_DB_CLOSE_ROTATE, error_r);
	}

	if (fuser->set.commit_limit > 0 &&
	    x->doc_updates >= fuser->set.commit_limit) {
		e_debug(backend->event,
			"Committing DB as update limit was reached; limit=%d",
			fuser->set.commit_limit);
		return fts_flatcurve_xapian_close_dbs(
			backend, FLATCURVE_XAPIAN_DB_CLOSE_WDB_COMMIT, error_r);
	}

	return 0;
}

/* Returns: 0 on success, -1 on error */
static int
fts_flatcurve_xapian_clear_document(struct flatcurve_fts_backend *backend,
				    const char **error_r)
{
	static const enum flatcurve_xapian_db_opts opts =
		ENUM_EMPTY(flatcurve_xapian_db_opts);

	struct flatcurve_xapian *x = backend->xapian;

	if (x->doc == NULL)
		return 0;

	struct flatcurve_xapian_db *xdb;
	int ret = fts_flatcurve_xapian_write_db_current(
			backend, opts, &xdb, error_r);
	if (ret <= 0)
		return ret;

	ret = 0;
	try {
		xdb->dbw->replace_document(x->doc_uid, *x->doc);
	} catch (std::bad_alloc &b) {
		i_fatal_status(FATAL_OUTOFMEM,
			"Out of memory when indexing mail (%s); UID=%d "
			"(Hint: increase indexing process vsz_limit or "
			"define smaller commit limit value in "
			"plugin { fts_flatcurve_commit_limit = ...})",
			b.what(), x->doc_uid);
	} catch (Xapian::Error &e) {
		*error_r = t_strdup_printf(
			"Could not write message data: uid=%u; %s",
			x->doc_uid,
			e.get_description().c_str());
		ret = -1;
	}

	if (x->doc_created)
		delete(x->doc);
	x->doc = NULL;
	x->doc_created = FALSE;
	x->doc_uid = 0;

	if (ret < 0)
		return -1;

	return fts_flatcurve_xapian_check_commit_limit(backend, xdb, error_r);
}

/* Returns: 0 on success, -1 on error */
static int
fts_flatcurve_xapian_close_db(struct flatcurve_fts_backend *backend,
			      struct flatcurve_xapian_db *xdb,
			      enum flatcurve_xapian_db_close opts,
			      const char **error_r)
{
	struct flatcurve_xapian *x = backend->xapian;

	if (fts_flatcurve_xapian_clear_document(backend, error_r) < 0)
		return -1;

	struct timeval start;
	i_gettimeofday(&start);

	bool commit = FALSE;
	if (xdb->dbw != NULL) {
		if (HAS_ANY_BITS(opts, FLATCURVE_XAPIAN_DB_CLOSE_WDB |
				       FLATCURVE_XAPIAN_DB_CLOSE_MBOX)) {
			int ret = 0;
			try {
				/* even if xapian documetation states that close
				auto-commits, GlassWritableDatabase::close() can
				fail to actually close the db if commit fails.
				We explicitly commit before invoking close to
				have a better chance to properly clean up */
				xdb->dbw->commit();
			}
			catch (Xapian::Error &e) {
				*error_r = t_strdup(e.get_description().c_str());
				ret = -1;
			}
			xdb->dbw->close();
			delete(xdb->dbw);
			xdb->dbw = NULL;
			commit = TRUE; // mark anyway as committed
			if (ret < 0)
				return -1;
		} else if (HAS_ANY_BITS(opts, FLATCURVE_XAPIAN_DB_CLOSE_WDB_COMMIT |
					      FLATCURVE_XAPIAN_DB_CLOSE_ROTATE)) {
			try {
				xdb->dbw->commit();
				commit = TRUE;
			}
			catch (Xapian::Error &e) {
				*error_r = t_strdup(e.get_description().c_str());
				return -1;
			}
		}
	}

	bool rotate = FALSE;
	if (commit) {
		struct timeval now;
		i_gettimeofday(&now);
		unsigned int elapsed =
			(unsigned int) timeval_diff_msecs(&now, &start);
		if (xdb->changes > 0)
			e_debug(backend->event, "Committed %u changes to DB "
				"(RW, %s) in %u.%03u secs", xdb->changes,
				xdb->dbpath->fname, elapsed / 1000, elapsed % 1000);

		xdb->changes = 0;
		x->doc_updates = 0;

		if (xdb->type == FLATCURVE_XAPIAN_DB_TYPE_CURRENT) {
			if (HAS_ALL_BITS(opts, FLATCURVE_XAPIAN_DB_CLOSE_ROTATE) ||
				(backend->fuser->set.rotate_time > 0 &&
				 elapsed > backend->fuser->set.rotate_time))
				rotate = TRUE;
		}
	}


	if (rotate) {
		const char *error;
		if (fts_flatcurve_xapian_lock(backend, &error) < 0)
			e_error(backend->event, "%s", error);
		else {
			const char *fname = p_strdup(x->pool, xdb->dbpath->fname);
			enum flatcurve_xapian_db_close flags =
				(enum flatcurve_xapian_db_close)
				(opts & FLATCURVE_XAPIAN_DB_CLOSE_MBOX);
			if (fts_flatcurve_xapian_create_current(
				backend, flags, &error) < 0)
				e_error(backend->event, "Error rotating DB (%s)",
					xdb->dbpath->fname);
			else
				e_debug(event_create_passthrough(backend->event)->
					set_name("fts_flatcurve_rotate")->
					add_str("mailbox", str_c(backend->boxname))->
					event(),
					"Rotating index (from: %s, to: %s)", fname,
					xdb->dbpath->fname);

			fts_flatcurve_xapian_unlock(backend);
		}
	}

	if (xdb->db != NULL &&
	    HAS_ANY_BITS(opts, FLATCURVE_XAPIAN_DB_CLOSE_DB |
			       FLATCURVE_XAPIAN_DB_CLOSE_MBOX)) {
		delete(xdb->db);
		xdb->db = NULL;
	}

	return 0;
}

/* Returns: 0 on success, -1 on error */
static int
fts_flatcurve_xapian_close_dbs(struct flatcurve_fts_backend *backend,
			       enum flatcurve_xapian_db_close opts,
			       const char **error_r)
{
	struct hash_iterate_context *iter;
	void *key, *val;
	struct flatcurve_xapian *x = backend->xapian;

	const char *error, *last_error = NULL;
	iter = hash_table_iterate_init(x->dbs);
	while (hash_table_iterate(iter, x->dbs, &key, &val)) {
		struct flatcurve_xapian_db *db =
			(struct flatcurve_xapian_db *)val;
		if (fts_flatcurve_xapian_close_db(backend, db, opts, &error) < 0) {
			if (last_error != NULL)
				e_error(backend->event, "%s", last_error);
			last_error = error;
		}
	}
	hash_table_iterate_deinit(&iter);
	if (last_error != NULL) {
		*error_r = last_error;
		return -1;
	}
	return 0;
}

/* Returns: 0 on success, -1 on error */
int fts_flatcurve_xapian_refresh(struct flatcurve_fts_backend *backend,
				 const char **error_r)
{
	return fts_flatcurve_xapian_close_dbs(
		backend, FLATCURVE_XAPIAN_DB_CLOSE_WDB, error_r);
}

/* Returns: 0 on success, -1 on error */
int fts_flatcurve_xapian_close(struct flatcurve_fts_backend *backend,
			       const char **error_r)
{
	struct flatcurve_xapian *x = backend->xapian;
	int ret = fts_flatcurve_xapian_close_dbs(
		backend, FLATCURVE_XAPIAN_DB_CLOSE_MBOX, error_r);

	hash_table_clear(x->dbs, TRUE);

	x->lock_path = NULL;
	x->dbw_current = NULL;
	x->shards = 0;

	if (x->db_read != NULL) {
		x->db_read->close();
		delete(x->db_read);
		x->db_read = NULL;
	}

	p_clear(x->pool);
	return ret;
}

static uint32_t
fts_flatcurve_xapian_get_last_uid_query(struct flatcurve_fts_backend *backend ATTR_UNUSED,
					Xapian::Database *db)
{
	Xapian::Enquire enquire(*db);
	Xapian::MSet m;

	enquire.set_docid_order(Xapian::Enquire::DESCENDING);
	enquire.set_query(Xapian::Query::MatchAll);

	m = enquire.get_mset(0, 1);
	return (m.empty())
		? 0 : m.begin().get_document().get_docid();
}

/* Returns: 0 on success, -1 on error */
int fts_flatcurve_xapian_get_last_uid(struct flatcurve_fts_backend *backend,
				      uint32_t *last_uid_r, const char **error_r)
{
	static const enum flatcurve_xapian_db_opts opts =
		(enum flatcurve_xapian_db_opts)
			(FLATCURVE_XAPIAN_DB_NOCREATE_CURRENT |
			 FLATCURVE_XAPIAN_DB_IGNORE_EMPTY);

	Xapian::Database *db;
	int ret = fts_flatcurve_xapian_read_db(backend, opts, &db, error_r);
	if (ret < 0)
		return ret;

	if (ret == 0) {
		*last_uid_r = 0;
		return 0;
	}

	try {
		/* Optimization: if last used ID still exists in  mailbox,
		 * this is a cheap call. */
		*last_uid_r = db->get_document(db->get_lastdocid()).get_docid();
		return 0;
	} catch (Xapian::DocNotFoundError &e) {
		/* Last used Xapian ID is no longer in the DB. Need
			* to do a manual search for the last existing ID. */
		*last_uid_r = fts_flatcurve_xapian_get_last_uid_query(backend, db);
		return 0;
	} catch (Xapian::InvalidArgumentError &e) {
		*last_uid_r = 0;
		return 0;
	}
}

/* Returns: 0 not found, 1 if found, -1 on error */
int fts_flatcurve_xapian_uid_exists(struct flatcurve_fts_backend *backend,
				    uint32_t uid, const char **error_r)
{
	static const enum flatcurve_xapian_db_opts opts =
		(enum flatcurve_xapian_db_opts)
			(FLATCURVE_XAPIAN_DB_NOCREATE_CURRENT |
			 FLATCURVE_XAPIAN_DB_IGNORE_EMPTY);

	if (fts_flatcurve_xapian_read_db(backend, opts, NULL, error_r) <= 0)
		return -1;
	return fts_flatcurve_xapian_uid_exists_db(backend, uid, NULL, error_r);
}

/* Returns: 0 not found, 1 deleted, -1 on error */
int fts_flatcurve_xapian_expunge(struct flatcurve_fts_backend *backend,
				 uint32_t uid, const char **error_r)
{
	struct flatcurve_xapian_db *xdb;

	if (fts_flatcurve_xapian_write_db_by_uid(
		backend, uid, &xdb, error_r) <= 0) {
		e_debug(backend->event, "Expunge failed uid=%u; UID not found",
			uid);
		return 0;
	}

	try {
		xdb->dbw->delete_document(uid);
		if (fts_flatcurve_xapian_check_commit_limit(
			backend, xdb, error_r) < 0)
			return -1;
		return 1;
	} catch (Xapian::Error &e) {
		*error_r = t_strdup_printf(
			"Failed to expunge uid=%u: %s",
			uid, e.get_description().c_str());
		return -1;
	}
}

/* Returns: TBD 0 not found, 1 deleted, -1 on error */
int
fts_flatcurve_xapian_init_msg(struct flatcurve_fts_backend_update_context *ctx,
			      const char **error_r)
{
	static const enum flatcurve_xapian_db_opts opts =
		ENUM_EMPTY(flatcurve_xapian_db_opts);

	struct flatcurve_xapian *x = ctx->backend->xapian;
	struct flatcurve_xapian_db *xdb;

	if (ctx->uid == x->doc_uid)
		/* already indexed, nothing else to do */
		return 1;

	if (fts_flatcurve_xapian_clear_document(ctx->backend, error_r) < 0)
		return -1;

	int ret = fts_flatcurve_xapian_write_db_current(
		ctx->backend, opts, &xdb, error_r);
	if (ret <= 0)
		/* error or x->dbw_current == NULL */
		return ret;
	try {
		(void)xdb->dbw->get_document(ctx->uid);
		/* document already existed */
		return 0;
	} catch (Xapian::DocNotFoundError &e) {
		x->doc = new Xapian::Document();
		x->doc_created = TRUE;
		x->doc_uid = ctx->uid;
		/* document did not exist */
		return 1;
	} catch (Xapian::Error &e) {
		ctx->ctx.failed = TRUE;
		*error_r = t_strdup(e.get_description().c_str());
		return -1;
	}
}

int
fts_flatcurve_xapian_index_header(struct flatcurve_fts_backend_update_context *ctx,
				  const unsigned char *data, size_t size,
				  const char **error_r)
{
	struct fts_flatcurve_user *fuser = ctx->backend->fuser;
	struct flatcurve_xapian *x = ctx->backend->xapian;

	int ret = fts_flatcurve_xapian_init_msg(ctx, error_r);
	if (ret <= 0)
		return ret;

	i_assert(uni_utf8_data_is_valid(data, size));

	T_BEGIN {
		char *hdr_name =
			str_lcase(t_strdup_noconst(str_c(ctx->hdr_name)));

		if (*hdr_name != '\0')
			x->doc->add_boolean_term(t_strdup_printf(
				FLATCURVE_XAPIAN_BOOLEAN_FIELD_PREFIX
				"%s", hdr_name));

		if (ctx->indexed_hdr)
			hdr_name = str_ucase(hdr_name);


		string_t *all_term = t_str_new(size);
		string_t *hdr_term = t_str_new(size + strlen(hdr_name));
		str_append(hdr_term, FLATCURVE_XAPIAN_HEADER_PREFIX);
		str_append(hdr_term, hdr_name);
		size_t hdr_term_start = str_len(hdr_term);

		const unsigned char *end = data + size;
		for(; end > data; data += uni_utf8_char_bytes((unsigned char) *data)) {
			size_t len = end - data;
			if (len < fuser->set.min_term_size)
				break;

			/* Capital ASCII letters at the beginning of a Xapian
			   term are treated as a "term prefix". Force to non-
			   -uppercase the first letter of the header value to
			   ensure the term is not confused with a
			   "term prefix". */

			str_truncate(all_term, 0);
			str_append(all_term, FLATCURVE_XAPIAN_ALL_HEADERS_PREFIX);
			str_append_c(all_term, i_tolower(*data));
			str_append_data(all_term, data + 1, len - 1);
			x->doc->add_term(str_c(all_term));

			if (ctx->indexed_hdr) {
				str_truncate(hdr_term, hdr_term_start);
				str_append_c(hdr_term, i_tolower(*data));
				str_append_data(hdr_term, data + 1, len - 1);
				x->doc->add_term(str_c(hdr_term));
			}

			if (!fuser->set.substring_search)
				break;
		}
	} T_END;
	return 1;
}

int
fts_flatcurve_xapian_index_body(struct flatcurve_fts_backend_update_context *ctx,
				const unsigned char *data_ro, size_t size,
				const char **error_r)
{
	struct fts_flatcurve_user *fuser = ctx->backend->fuser;
	struct flatcurve_xapian *x = ctx->backend->xapian;

	int ret = fts_flatcurve_xapian_init_msg(ctx, error_r);
	if (ret <= 0)
		return ret;

	i_assert(uni_utf8_data_is_valid(data_ro, size));

	T_BEGIN {
		string_t *term = t_str_new(size);
		str_append_data(term, data_ro, size);

		char *data = str_c_modifiable(term);
		const char *end = data + str_len(term);
		for(; end > data; data += uni_utf8_char_bytes((unsigned char) *data)) {
			size_t len = end - data;
			if (len < fuser->set.min_term_size)
				break;

			/* Capital ASCII letters at the beginning of a Xapian term are
			treated as a "term prefix". Check for a leading ASCII
			capital, and temporary lowercase it in place if necessary,
			to ensure the term is not confused with a "term prefix". */
			*data = i_tolower(*data);
			x->doc->add_term(data);

			if (!fuser->set.substring_search)
				break;
		}
	} T_END;

	return 1;
}

/* Returns: 0 if index doesn't exist, 1 on deletion, -1 on error */
int fts_flatcurve_xapian_delete_index(struct flatcurve_fts_backend *backend,
				      const char **error_r)
{
	const char *error;
	int ret = fts_flatcurve_xapian_close(backend, error_r);
	if (fts_flatcurve_xapian_delete(backend, NULL, &error) < 0) {
		if (ret < 0)
			e_error(backend->event, "%s", error);
		else
			*error_r = error;
		ret = -1;
	}
	return ret;
}

/* Returns: 0 on success, -1 on error */
static int
fts_flatcurve_xapian_optimize_rebuild(struct flatcurve_fts_backend *backend,
				      Xapian::Database *db,
				      struct flatcurve_xapian_db_path *path,
				      const char **error_r)
{
	struct flatcurve_xapian *x = backend->xapian;

	/* Create the optimize shard. */
	struct flatcurve_xapian_db *xdb =
		p_new(x->pool, struct flatcurve_xapian_db, 1);
	xdb->dbpath = path;
	xdb->type = FLATCURVE_XAPIAN_DB_TYPE_OPTIMIZE;

	if (fts_flatcurve_xapian_write_db_get(
		backend, xdb, FLATCURVE_XAPIAN_WDB_CREATE, error_r) < 0)
		return -1;

	Xapian::Enquire enquire(*db);
	enquire.set_docid_order(Xapian::Enquire::ASCENDING);
	enquire.set_query(Xapian::Query::MatchAll);

	Xapian::MSet mset = enquire.get_mset(0, db->get_doccount());
	Xapian::MSetIterator iter = mset.begin();

	unsigned int updates = 0;
	for (iter = mset.begin(); iter != mset.end(); ++iter) {
		Xapian::Document doc = iter.get_document();
		try {
	                xdb->dbw->replace_document(doc.get_docid(), doc);
			if (++updates > FLATCURVE_MANUAL_OPTIMIZE_COMMIT_LIMIT) {
				xdb->dbw->commit();
				updates = 0;
			}
	        } catch (Xapian::Error &e) {
			*error_r = t_strdup(e.get_description().c_str());
			return -1;
		}
	}

	return fts_flatcurve_xapian_close_db(
			backend, xdb, FLATCURVE_XAPIAN_DB_CLOSE_WDB, error_r);
}

/* Returns: 0 on success, -1 on error */
static int
fts_flatcurve_xapian_optimize_box_do(struct flatcurve_fts_backend *backend,
				     Xapian::Database *db, const char **error_r)
{
	static const enum flatcurve_xapian_db_opts opts =
		ENUM_EMPTY(flatcurve_xapian_db_opts);
	static const enum flatcurve_xapian_wdb wopts =
		ENUM_EMPTY(flatcurve_xapian_wdb);

	struct flatcurve_xapian *x = backend->xapian;

	/* We need to lock all of the mailboxes so nothing changes while we
	 * are optimizing. */

	void *key, *val;
	struct hash_iterate_context *hiter = hash_table_iterate_init(x->dbs);
	while (hash_table_iterate(hiter, x->dbs, &key, &val)) {
		struct flatcurve_xapian_db *db = (struct flatcurve_xapian_db *)val;
		if (fts_flatcurve_xapian_write_db_get(
			backend, db, wopts, error_r) < 0)
			return -1;
	}
	hash_table_iterate_deinit(&hiter);

	/* Create the optimize target. */
	struct flatcurve_xapian_db_path *dbpath =
		fts_flatcurve_xapian_create_db_path(
			backend, FLATCURVE_XAPIAN_DB_OPTIMIZE);
	if (fts_flatcurve_xapian_delete(backend, dbpath, error_r) < 0)
		return -1;

	struct timeval start;
	i_gettimeofday(&start);

	bool failed = FALSE;
	try {
		(void)db->reopen();
		db->compact(dbpath->path, Xapian::DBCOMPACT_NO_RENUMBER |
					  Xapian::DBCOMPACT_MULTIPASS |
					  Xapian::Compactor::FULLER);
	} catch (Xapian::InvalidOperationError &e) {
		/* This exception is not as specific as it could be...
		 * but the likely reason it happens is due to
		 * Xapian::DBCOMPACT_NO_RENUMBER and shards having disjoint
		 * ranges of UIDs (e.g. shard 1 = 1..2, shard 2 = 2..3).
		 * Xapian, as of 1.4.18, cannot handle this situation.
		 * Since we will never be able to compact this data unless
		 * we do something about it, the options are either:
		 *   1) delete the index totally and start fresh (not great
		 *      for large mailboxes), or
		 *   2) to incrementally build the optimized DB by walking
		 *      through all DBs and copying, ignoring duplicate
		 *      documents.
		 * Let's try to be awesome and do the latter. */
		failed = fts_flatcurve_xapian_optimize_rebuild(
				backend, db, dbpath, error_r) < 0;
		if (!failed)
			e_debug(backend->event, "Native optimize failed, "
				"falling back to manual optimization; %s",
				e.get_description().c_str());
	} catch (Xapian::Error &e) {
		*error_r = t_strdup(e.get_description().c_str());
		failed = TRUE;
	}
	if (failed) {
		e_error(backend->event, "Optimize failed: %s", *error_r);
		return 0;
	}

	/* Delete old indexes. */
	struct flatcurve_xapian_db_iter *iter =
		fts_flatcurve_xapian_db_iter_init(backend, opts);

	int ret = 0;
	while (fts_flatcurve_xapian_db_iter_next(iter)) {
		if (iter->type != FLATCURVE_XAPIAN_DB_TYPE_OPTIMIZE &&
		    iter->type != FLATCURVE_XAPIAN_DB_TYPE_LOCK) {
			if (fts_flatcurve_xapian_delete(
				backend, iter->path, error_r) < 0) {
				ret = -1;
				break;
			}
		}
	}
	const char *error;
	if (fts_flatcurve_xapian_db_iter_deinit(&iter, &error) < 0) {
		if (ret < 0)
			e_error(backend->event, "%s", error);
		else
			*error_r = error;
		ret = -1;
	}
	if (ret < 0)
		return -1;

	/* Rename optimize index to an active index. */
	if (fts_flatcurve_xapian_rename_db(backend, dbpath, NULL, error_r) < 0 ||
	    fts_flatcurve_xapian_delete(backend, dbpath, error_r) < 0)
		return -1;

	struct timeval now;
	i_gettimeofday(&now);
	unsigned int elapsed = (unsigned int) timeval_diff_msecs(&now, &start);
	e_debug(backend->event, "Optimized DB in %u.%03u secs",
				elapsed / 1000, elapsed % 1000);

	return 0;
}

/* Returns: 0 on success, -1 on error */
int fts_flatcurve_xapian_optimize_box(struct flatcurve_fts_backend *backend,
				      const char **error_r)
{
	static const enum flatcurve_xapian_db_opts opts =
		(enum flatcurve_xapian_db_opts)
			(FLATCURVE_XAPIAN_DB_NOCREATE_CURRENT |
			 FLATCURVE_XAPIAN_DB_IGNORE_EMPTY);

	Xapian::Database *db;
	int ret;
	if ((ret = fts_flatcurve_xapian_read_db(
		backend, opts, &db, error_r)) <= 0)
		return ret;

	if (backend->xapian->deinit &&
	    !fts_flatcurve_xapian_need_optimize(backend)) {
		return fts_flatcurve_xapian_close(backend, error_r);
	}

	e_debug(event_create_passthrough(backend->event)->
		set_name("fts_flatcurve_optimize")->
		add_str("mailbox", str_c(backend->boxname))->event(),
		"Optimizing");

	ret = 0;
	if (fts_flatcurve_xapian_lock(backend, error_r) < 0 ||
	    fts_flatcurve_xapian_optimize_box_do(backend, db, error_r) < 0)
		ret = -1;

	const char *error;
	if (fts_flatcurve_xapian_close(backend, &error) < 0) {
		if (ret < 0)
			e_error(backend->event, "%s", error);
		else
			*error_r = error;
		ret = -1;
	}
	fts_flatcurve_xapian_unlock(backend);
	return ret;
}

static void
fts_flatcurve_build_query_arg_term(struct flatcurve_fts_query *query,
				   struct mail_search_arg *arg,
				   const char *term)
{
	const char *hdr;
	Xapian::Query::op op = Xapian::Query::OP_INVALID;
	Xapian::Query *oldq, q;
	struct flatcurve_fts_query_xapian *x = query->xapian;

	if (x->query != NULL) {
		if ((query->flags & FTS_LOOKUP_FLAG_AND_ARGS) != 0) {
			op = Xapian::Query::OP_AND;
			str_append(query->qtext, " AND ");
		} else {
			op = Xapian::Query::OP_OR;
			str_append(query->qtext, " OR ");
		}
	}

	if (arg->match_not)
		str_append(query->qtext, "NOT ");

	switch (arg->type) {
	case SEARCH_TEXT:
		q = Xapian::Query(Xapian::Query::OP_OR,
			Xapian::Query(Xapian::Query::OP_WILDCARD,
				t_strdup_printf("%s%s",
					FLATCURVE_XAPIAN_ALL_HEADERS_PREFIX,
					term)),
			Xapian::Query(Xapian::Query::OP_WILDCARD, term));
		str_printfa(query->qtext, "(%s:%s* OR %s:%s*)",
			    FLATCURVE_XAPIAN_ALL_HEADERS_QP, term,
			    FLATCURVE_XAPIAN_BODY_QP, term);
		break;

	case SEARCH_BODY:
		q = Xapian::Query(Xapian::Query::OP_WILDCARD, term);
		str_printfa(query->qtext, "%s:%s*",
			    FLATCURVE_XAPIAN_BODY_QP, term);
		break;

	case SEARCH_HEADER:
	case SEARCH_HEADER_ADDRESS:
	case SEARCH_HEADER_COMPRESS_LWSP:
		if (*term != '\0') {
			if (fts_header_want_indexed(arg->hdr_field_name)) {
				q = Xapian::Query(
					Xapian::Query::OP_WILDCARD,
					t_strdup_printf("%s%s%s",
						FLATCURVE_XAPIAN_HEADER_PREFIX,
						t_str_ucase(arg->hdr_field_name),
						term));
				str_printfa(query->qtext, "%s%s:%s*",
					    FLATCURVE_XAPIAN_HEADER_QP,
					    t_str_lcase(arg->hdr_field_name),
					    term);
			} else {
				q = Xapian::Query(
					Xapian::Query::OP_WILDCARD,
					t_strdup_printf("%s%s",
						FLATCURVE_XAPIAN_ALL_HEADERS_PREFIX,
						term));
				str_printfa(query->qtext, "%s:%s*",
					    FLATCURVE_XAPIAN_ALL_HEADERS_QP,
					    term);
				/* Non-indexed headers only match if it
				 * appears in the general pool of header
				 * terms for the message, not to a specific
				 * header, so this is only a maybe match. */
				query->maybe = TRUE;
			}
		} else {
			hdr = t_str_lcase(arg->hdr_field_name);
			q = Xapian::Query(t_strdup_printf("%s%s",
				FLATCURVE_XAPIAN_BOOLEAN_FIELD_PREFIX, hdr));
			str_printfa(query->qtext, "%s:%s",
				    FLATCURVE_XAPIAN_HEADER_BOOL_QP, hdr);
		}
		break;
	default:
		i_unreached();
	}

	if (arg->match_not)
		q = Xapian::Query(Xapian::Query::OP_AND_NOT,
				  Xapian::Query::MatchAll, q);

	if (x->query == NULL)
		x->query = new Xapian::Query(q);
	else {
		oldq = x->query;
		x->query = new Xapian::Query(op, *(x->query), q);
		delete(oldq);
	}
}

static void
fts_flatcurve_build_query_arg(struct flatcurve_fts_query *query,
			      struct mail_search_arg *arg)
{
	if (arg->no_fts)
		return;

	switch (arg->type) {
	case SEARCH_TEXT:
	case SEARCH_BODY:
	case SEARCH_HEADER:
	case SEARCH_HEADER_ADDRESS:
	case SEARCH_HEADER_COMPRESS_LWSP:
		/* Valid search term. Set match_always, as required by FTS
		 * API, to avoid this argument being looked up later via
		 * regular search code. */
		arg->match_always = TRUE;
		break;

	case SEARCH_MAILBOX:
		/* doveadm will pass this through in 'doveadm search'
		 * commands with a 'mailbox' search argument. The code has
		 * already handled setting the proper mailbox by this point
		 * so just ignore this. */
		return;

	case SEARCH_OR:
	case SEARCH_SUB:
		/* FTS API says to ignore these. */
		return;

	default:
		/* We should never get here - this is a search argument that
		 * we don't understand how to handle that has leaked to this
		 * point. For performance reasons, we will ignore this
		 * argument and err on the side of returning too many
		 * results (rather than falling back to slow, manual
		 * search). */
		return;
	}

	if (strchr(arg->value.str, ' ') == NULL) {
		/* Prepare search term.
		 * This includes existence searches where arg is "" */
		fts_flatcurve_build_query_arg_term(query, arg, arg->value.str);
	} else {
		/* Phrase searching is not supported natively, so we can only do
		 * single term searching with Xapian (FTS core provides index
		 * terms without positional context).

		 * FTS core will send both the phrase search and individual search
		 * terms separately as part of the same query. Therefore, if we
		 * encounter a multi-term search, just ignore it */
	}
}

void
fts_flatcurve_xapian_build_query_match_all(struct flatcurve_fts_query *query)
{
	query->xapian = p_new(query->pool, struct flatcurve_fts_query_xapian, 1);
	query->qtext = str_new_const(query->pool, "[Match All]", 11);
	query->xapian->query = new Xapian::Query(Xapian::Query::MatchAll);
}

/* Returns: 0 on success, -1 on error */
void fts_flatcurve_xapian_build_query(struct flatcurve_fts_query *query)
{
	struct mail_search_arg *args;

	query->xapian = p_new(query->pool, struct flatcurve_fts_query_xapian, 1);
	for (args = query->args; args != NULL ; args = args->next)
		fts_flatcurve_build_query_arg(query, args);
}

struct fts_flatcurve_xapian_query_iter *
fts_flatcurve_xapian_query_iter_init(struct flatcurve_fts_query *query)
{
	struct fts_flatcurve_xapian_query_iter *iter;
	iter = new fts_flatcurve_xapian_query_iter();
	iter->query = query;
	iter->result = p_new(query->pool,
			     struct fts_flatcurve_xapian_query_result, 1);
	return iter;
}

bool
fts_flatcurve_xapian_query_iter_next(struct fts_flatcurve_xapian_query_iter *iter,
				     struct fts_flatcurve_xapian_query_result **result_r)
{
	static const enum flatcurve_xapian_db_opts opts =
		ENUM_EMPTY(flatcurve_xapian_db_opts);

	if (iter->error != NULL)
		return FALSE;

	Xapian::MSet m;
	if (iter->enquire == NULL) {
		if (iter->query->xapian->query == NULL)
			return FALSE;

		const char *error;
		int ret = fts_flatcurve_xapian_read_db(
			iter->query->backend, opts, &iter->db, &error);
		if (ret < 0)
			iter->error = i_strdup(error);
		if (ret <= 0)
			return FALSE;

		iter->enquire = new Xapian::Enquire(*iter->db);
		iter->enquire->set_docid_order(
				Xapian::Enquire::DONT_CARE);
		iter->enquire->set_query(*iter->query->xapian->query);

		try {
			m = iter->enquire->get_mset(0, iter->db->get_doccount());
		} catch (Xapian::DatabaseModifiedError &e) {
			/* Per documentation, this is only thrown if more than
			 * one change has been made to the database. To
			 * resolve you need to reopen the DB (Xapian can
			 * handle a single snapshot of a modified DB natively,
			 * so this only occurs if there have been multiple
			 * writes). However, we ALWAYS want to use the
			 * most up-to-date version, so we have already
			 * explicitly called reopen() above. Thus, we should
			 * never see this exception. */
			i_unreached();
		}

		iter->mset_iter = m.begin();
	}

	if (iter->mset_iter == m.end())
		return FALSE;

	iter->result->score = iter->mset_iter.get_weight();
	/* MSet docid can be an "interleaved" docid generated by
	 * Xapian::Database when handling multiple DBs at once. Instead, we
	 * want the "unique docid", which is obtained by looking at the
	 * doc id from the Document object itself. */
	iter->result->uid = iter->mset_iter.get_document().get_docid();
	++iter->mset_iter;

	*result_r = iter->result;
	return TRUE;
}

/* Returns: 0 on success, -1 on error */
int
fts_flatcurve_xapian_query_iter_deinit(struct fts_flatcurve_xapian_query_iter **_iter,
				       const char **error_r)
{
	struct fts_flatcurve_xapian_query_iter *iter = *_iter;
	*_iter = NULL;

	p_free(iter->query->pool, iter->result);
	if (iter->enquire != NULL)
		delete(iter->enquire);

	int ret = 0;
	if (iter->error != NULL) {
		*error_r = t_strdup(iter->error);
		i_free(iter->error);
		ret = -1;
	}
	delete(iter);
	return ret;
}

/* Returns: 0 on success, -1 on error */
int fts_flatcurve_xapian_run_query(struct flatcurve_fts_query *query,
				   struct flatcurve_fts_result *r,
				   const char **error_r)
{
	struct fts_flatcurve_xapian_query_iter *iter;
	struct fts_flatcurve_xapian_query_result *result;
	struct fts_score_map *score;

	iter = fts_flatcurve_xapian_query_iter_init(query);
	while (fts_flatcurve_xapian_query_iter_next(iter, &result)) {
		seq_range_array_add(&r->uids, result->uid);
		score = array_append_space(&r->scores);
		score->score = (float)result->score;
		score->uid = result->uid;
	}
	return fts_flatcurve_xapian_query_iter_deinit(&iter, error_r);
}

void fts_flatcurve_xapian_destroy_query(struct flatcurve_fts_query *query)
{
	delete(query->xapian->query);
}

const char *fts_flatcurve_xapian_library_version()
{
	return Xapian::version_string();
}
