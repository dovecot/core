/* Copyright (c) Dovecot authors, see top-level COPYING file */

/* Tests for the acl-rights.cache file: the on-disk format, the lookup
   accessors, incremental updates, eviction, verify-after-read and the
   nonowner lookup iteration's failure semantics. */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "strescape.h"
#include "ioloop.h"
#include "test-common.h"
#include "mail-storage.h"
#include "mailbox-list.h"
#include "acl-storage.h"
#include "acl-api-private.h"
#include "acl-backend-vfile.h"
#include "file-create-locked.h"
#include "acl-plugin.h"
#include "acl-rights-cache.h"
#include "test-acl-common.h"

#include <stdio.h>
#include <unistd.h>
#include <utime.h>
#include <sys/stat.h>

#define TEST_MAILBOX "Test"
#define TEST_MAILBOX2 "Test2"
#define TEST_MAILBOX_DIGITS "12345"
#define TEST_UPDATE_ID "user="TEST_ACL_USER

/* NULL-terminated userdb field list */
#define TEST_INPUT(...) ((const char *const []){ __VA_ARGS__, NULL })
/* NULL-terminated right name list for acl_rights_update_import() */
#define TEST_RIGHTS(...) ((const char *const []){ __VA_ARGS__, NULL })

static const char *test_acl_cache_path(void)
{
	const char *root_dir;
	enum mailbox_list_path_type type;

	if (!acl_backend_get_root_dir(test_acl.backend, &root_dir, &type))
		i_fatal("acl_backend_get_root_dir() failed");
	return t_strconcat(root_dir, "/"ACL_RIGHTS_CACHE, NULL);
}

static struct acl_rights_cache_file *test_acl_cache_file(void)
{
	return test_acl.backend->rights_cache_file;
}

static int
test_acl_do_update(struct acl_object *aclobj, const char *id,
		   const char *const *rights,
		   enum acl_modify_mode modify_mode,
		   enum acl_modify_mode neg_modify_mode)
{
	struct acl_rights_update update = {
		.modify_mode = modify_mode,
		.neg_modify_mode = neg_modify_mode,
	};
	const char *error;

	if (acl_rights_update_import(&update, id, rights, &error) < 0)
		i_fatal("acl_rights_update_import(%s) failed: %s", id, error);
	return acl_object_update(aclobj, &update);
}

static void test_acl_grant(const char *name, const char *id,
			   const char *const *rights)
{
	struct acl_object *aclobj =
		acl_object_init_from_name(test_acl.backend, name);

	test_assert(test_acl_do_update(aclobj, id, rights,
				       ACL_MODIFY_MODE_ADD,
				       ACL_MODIFY_MODE_ADD) == 0);
	acl_object_deinit(&aclobj);
}

/* The cached rights of the mailbox as "<id> <rights>[ -<neg rights>]"
   entries separated by ", ", sorted by identifier - neither the writer's
   entry order nor the parser's is part of the format. */
static const char *test_acl_cache_get(const char *name)
{
	ARRAY_TYPE(acl_rights) rights;
	ARRAY_TYPE(const_string) strings;
	const struct acl_rights *right;
	pool_t pool = pool_alloconly_create("test cache get", 1024);

	t_array_init(&rights, 8);
	t_array_init(&strings, 8);
	acl_rights_cache_file_get(test_acl_cache_file(), name, pool, &rights);
	array_foreach(&rights, right) {
		string_t *str = t_str_new(64);

		str_append(str, acl_rights_get_id(right));
		if (right->rights != NULL) {
			str_append_c(str, ' ');
			str_append(str, t_strarray_join(right->rights, " "));
		}
		if (right->neg_rights != NULL) {
			str_append(str, " -");
			str_append(str, t_strarray_join(right->neg_rights, " "));
		}
		const char *line = str_c(str);
		array_push_back(&strings, &line);
	}
	array_sort(&strings, i_strcmp_p);
	array_append_zero(&strings);
	pool_unref(&pool);
	return t_strarray_join(array_front(&strings), ", ");
}

/* The mailbox's line in the raw cache file, "" if it has none. If the file
   had several lines for it, they'd be returned separated by "|". */
static const char *test_acl_cache_raw_lines(const char *name)
{
	const char *cache = test_acl_read_file(test_acl_cache_path());
	string_t *str = t_str_new(128);

	if (cache == NULL)
		return NULL;
	for (const char *const *line = t_strsplit(cache, "\n");
	     *line != NULL; line++) {
		/* <mtime> TAB <flags> TAB <name> ... */
		const char *const *fields = t_strsplit_tabescaped(*line);

		if (str_array_length(fields) < 3 ||
		    strcmp(fields[2], name) != 0)
			continue;
		if (str_len(str) > 0)
			str_append_c(str, '|');
		str_append(str, *line);
	}
	return str_c(str);
}

/* The flags field of the mailbox's line in the raw cache file */
static const char *test_acl_cache_flags(const char *name)
{
	const char *line = test_acl_cache_raw_lines(name);

	if (line == NULL || *line == '\0')
		return NULL;
	return t_strsplit_tabescaped(line)[1];
}

static const char *test_acl_cache_iterate(void)
{
	struct acl_mailbox_list_context *ctx;
	string_t *str = t_str_new(128);
	const char *name;

	ctx = acl_backend_nonowner_lookups_iter_init(test_acl.backend);
	while (acl_backend_nonowner_lookups_iter_next(ctx, &name)) {
		if (str_len(str) > 0)
			str_append_c(str, ' ');
		str_append(str, name);
	}
	test_assert(acl_backend_nonowner_lookups_iter_deinit(&ctx) >= 0);
	return str_c(str);
}

static void test_acl_rights_cache_format(void)
{
	test_begin("acl rights cache format");
	test_acl_user_init(NULL);
	test_acl_mailbox_create(TEST_MAILBOX);
	test_acl_mailbox_create(TEST_MAILBOX_DIGITS);

	/* a quoted identifier with a space, a negative right and anyone */
	test_acl_write_file(test_acl_local_path(TEST_MAILBOX),
			    "\"user=space user\" lr\n"
			    "-user=negative l\n"
			    "anyone lr\n");
	/* an all-digit mailbox name must not be confused with the mtime
	   column */
	test_acl_write_file(test_acl_local_path(TEST_MAILBOX_DIGITS),
			    TEST_UPDATE_ID" r\n");

	struct acl_backend_vfile *backend =
		container_of(test_acl.backend, struct acl_backend_vfile,
			     backend);
	test_assert(acl_rights_cache_rebuild(backend) == 0);
	test_assert(acl_rights_cache_file_exists(test_acl_cache_file()) == 1);

	/* everything round-trips through the TSV format */
	test_assert_strcmp(test_acl_cache_get(TEST_MAILBOX),
			   "anyone lookup read, user=negative -lookup, user=space user lookup read");
	test_assert_strcmp(test_acl_cache_get(TEST_MAILBOX_DIGITS),
			   TEST_UPDATE_ID" read");

	/* a version line, then one line per mailbox: mtime, flags, name and
	   an identifier + rights pair for each right */
	const char *cache = test_acl_read_file(test_acl_cache_path());
	test_assert(cache != NULL && str_begins_with(cache, "V1\n"));
	const char *line = test_acl_cache_raw_lines(TEST_MAILBOX);
	test_assert(strchr(line, '|') == NULL);
	test_assert(str_array_length(t_strsplit_tabescaped(line)) == 3 + 2 * 3);
	line = test_acl_cache_raw_lines(TEST_MAILBOX_DIGITS);
	test_assert(strstr(line, "\t-\t"TEST_MAILBOX_DIGITS"\t"
			   TEST_UPDATE_ID"\tr") != NULL);

	test_acl_user_deinit();
	test_end();
}

/* The namespace default ACL object has an empty name and reads
   <ACL root>/dovecot-acl. It must never be written to
   the cache - an empty name would make the whole file unparseable. maildir
   can't have the file (the mail root is INBOX's directory), so use sdbox. */
static void test_acl_rights_cache_default_acl(void)
{
	const struct acl_mask *mask;
	const char *cache_path, *root_acl_path;

	test_begin("acl rights cache ignores the default ACL object");
	test_acl_user_init_driver("sdbox", NULL);
	test_acl_mailbox_create(TEST_MAILBOX);
	test_acl_grant(TEST_MAILBOX, TEST_UPDATE_ID,
		       TEST_RIGHTS(MAIL_ACL_LOOKUP, MAIL_ACL_READ));
	test_assert_strcmp(test_acl_cache_get(TEST_MAILBOX),
			   TEST_UPDATE_ID" lookup read");

	cache_path = test_acl_cache_path();
	root_acl_path = t_strconcat(
		t_strdup_until(cache_path, strrchr(cache_path, '/')),
		"/dovecot-acl", NULL);
	test_acl_write_file(root_acl_path, "anyone l\n");
	test_assert(acl_backend_get_default_rights(test_acl.backend,
						   &mask) == 0);

	/* the cache is still readable and unchanged */
	test_assert(acl_rights_cache_file_refresh(test_acl_cache_file()) == 1);
	test_assert_strcmp(test_acl_cache_raw_lines(""), "");
	test_assert_strcmp(test_acl_cache_get(TEST_MAILBOX),
			   TEST_UPDATE_ID" lookup read");

	test_acl_user_deinit();
	test_end();
}

static void test_acl_rights_cache_markers(void)
{
	const char *cache_path;

	test_begin("acl rights cache markers");
	test_acl_user_init(NULL);
	test_acl_mailbox_create(TEST_MAILBOX);
	test_acl_grant(TEST_MAILBOX, TEST_UPDATE_ID,
		       TEST_RIGHTS(MAIL_ACL_LOOKUP, MAIL_ACL_READ));
	cache_path = test_acl_cache_path();

	/* a line with only the marker flag parses as an entry without
	   rights */
	test_acl_write_file(cache_path,
		t_strconcat(test_acl_read_file(cache_path),
			    "0\tm\tMarkerBox\n", NULL));
	test_assert(acl_rights_cache_file_refresh(test_acl_cache_file()) == 1);

	/* there are no rights that could be served from a marker */
	test_assert(!acl_rights_cache_file_have_any(test_acl_cache_file(),
						    "MarkerBox", NULL));
	test_assert_strcmp(test_acl_cache_get("MarkerBox"), "");
	/* but the mailbox is part of the nonowner iteration */
	test_assert_strcmp(test_acl_cache_iterate(), "MarkerBox "TEST_MAILBOX);

	test_acl_user_deinit();
	test_end();
}

/* TRUE if the mailbox's line in the cache file has the marker flag */
static bool test_acl_cache_has_marker(const char *name)
{
	const char *flags = test_acl_cache_flags(name);

	return flags != NULL && strchr(flags, 'm') != NULL;
}

/* TRUE if the nonowner iteration returns the mailbox */
static bool test_acl_cache_iterates(const char *name)
{
	return strstr(t_strdup_printf(" %s ", test_acl_cache_iterate()),
		      t_strdup_printf(" %s ", name)) != NULL;
}

/* A mailbox that gets its nonowner lookup right from the configuration
   keeps its marker next to the ACL file's rights. It stays part of the
   nonowner iteration whatever the file says. */
static void test_acl_rights_cache_marker_with_file_rights(void)
{
	struct acl_object *aclobj;
	const char *acl_path;
	struct stat st;
	struct utimbuf ut;

	test_begin("acl rights cache marker next to file rights");
	/* acl anyone { rights = lr } */
	test_acl_user_init(TEST_INPUT("acl+=anyone",
				      "acl/anyone/acl_rights=lr"));
	test_acl_mailbox_create(TEST_MAILBOX);

	/* an ACL update: the file gives a user the read right only */
	test_acl_grant(TEST_MAILBOX, TEST_UPDATE_ID,
		       TEST_RIGHTS(MAIL_ACL_READ));
	test_assert_strcmp(test_acl_cache_get(TEST_MAILBOX),
			   TEST_UPDATE_ID" read");
	test_assert(test_acl_cache_has_marker(TEST_MAILBOX));
	test_assert(test_acl_cache_iterates(TEST_MAILBOX));

	/* the ACL file changes without an ACL update */
	acl_path = test_acl_local_path(TEST_MAILBOX);
	test_acl_write_file(acl_path, TEST_UPDATE_ID" rw\n");
	if (stat(acl_path, &st) < 0)
		i_fatal("stat(%s) failed: %m", acl_path);
	ut.actime = st.st_atime;
	ut.modtime = st.st_mtime + 10;
	if (utime(acl_path, &ut) < 0)
		i_fatal("utime(%s) failed: %m", acl_path);
	aclobj = acl_object_init_from_name(test_acl.backend, TEST_MAILBOX);
	(void)test_acl_my_rights(aclobj);
	acl_object_deinit(&aclobj);
	test_assert_strcmp(test_acl_cache_get(TEST_MAILBOX),
			   TEST_UPDATE_ID" read write");
	test_assert(test_acl_cache_has_marker(TEST_MAILBOX));
	test_assert(test_acl_cache_iterates(TEST_MAILBOX));

	/* a rebuild */
	test_assert(acl_backend_nonowner_lookups_rebuild(test_acl.backend,
							  FALSE) == 0);
	test_assert_strcmp(test_acl_cache_get(TEST_MAILBOX),
			   TEST_UPDATE_ID" read write");
	test_assert(test_acl_cache_has_marker(TEST_MAILBOX));
	test_assert(test_acl_cache_iterates(TEST_MAILBOX));

	test_acl_user_deinit();
	test_end();
}

static void test_acl_rights_cache_partial_parse(void)
{
	const char *cache_path;

	test_begin("acl rights cache partial parse");
	test_acl_user_init(NULL);
	test_acl_mailbox_create(TEST_MAILBOX);
	test_acl_grant(TEST_MAILBOX, TEST_UPDATE_ID,
		       TEST_RIGHTS(MAIL_ACL_LOOKUP, MAIL_ACL_READ));
	cache_path = test_acl_cache_path();

	/* a broken line after a valid one - nothing of the file may be
	   installed */
	test_acl_write_file(cache_path,
		t_strconcat(test_acl_read_file(cache_path), "junk\n", NULL));
	test_expect_error_string("Invalid number of fields");
	test_assert(acl_rights_cache_file_refresh(test_acl_cache_file()) == -1);
	test_expect_no_more_errors();
	test_assert_strcmp(test_acl_cache_get(TEST_MAILBOX), "");

	test_acl_user_deinit();
	test_end();
}

/* A failed parse leaves nothing in memory, and the next file written in
   place may have the same inode, size and mtime as the last good one. It
   must be parsed, not taken as unchanged. */
static void test_acl_rights_cache_reparse_after_failure(void)
{
	const char *cache_path, *good;
	struct stat st;

	test_begin("acl rights cache re-parses after a failed parse");
	test_acl_user_init(NULL);
	test_acl_mailbox_create(TEST_MAILBOX);
	test_acl_grant(TEST_MAILBOX, TEST_UPDATE_ID,
		       TEST_RIGHTS(MAIL_ACL_LOOKUP, MAIL_ACL_READ));
	cache_path = test_acl_cache_path();
	good = t_strdup(test_acl_read_file(cache_path));
	test_assert(stat(cache_path, &st) == 0);

	test_acl_write_file(cache_path, "V1\njunk\n");
	test_expect_error_string("Invalid number of fields");
	test_assert(acl_rights_cache_file_refresh(test_acl_cache_file()) == -1);
	test_expect_no_more_errors();
	test_assert_strcmp(test_acl_cache_get(TEST_MAILBOX), "");

	/* the good content again, with the old timestamps */
	test_acl_write_file(cache_path, good);
#ifdef HAVE_ST_NSECS
	struct timespec ts[2] = {
		{ .tv_sec = ST_ATIME_SEC(st), .tv_nsec = ST_ATIME_NSEC(st) },
		{ .tv_sec = ST_MTIME_SEC(st), .tv_nsec = ST_MTIME_NSEC(st) },
	};
	test_assert(utimensat(AT_FDCWD, cache_path, ts, 0) == 0);
#else
	struct utimbuf ut = { .actime = st.st_atime, .modtime = st.st_mtime };
	test_assert(utime(cache_path, &ut) == 0);
#endif
	test_assert(acl_rights_cache_file_refresh(test_acl_cache_file()) == 1);
	test_assert_strcmp(test_acl_cache_get(TEST_MAILBOX),
			   TEST_UPDATE_ID" lookup read");

	test_acl_user_deinit();
	test_end();
}

/* The cache is locked with the storage's lock_method, so each of them has
   to work. */
static void test_acl_rights_cache_lock_methods(void)
{
	static const char *const lock_methods[] = {
		"fcntl", "flock", "dotlock"
	};
	const char *lock_path;

	test_begin("acl rights cache lock methods");
	for (unsigned int i = 0; i < N_ELEMENTS(lock_methods); i++) {
		test_acl_user_init(TEST_INPUT(t_strconcat("lock_method=",
							  lock_methods[i],
							  NULL)));
		test_acl_mailbox_create(TEST_MAILBOX);
		test_acl_grant(TEST_MAILBOX, TEST_UPDATE_ID,
			       TEST_RIGHTS(MAIL_ACL_LOOKUP, MAIL_ACL_READ));
		test_assert_strcmp_idx(test_acl_cache_get(TEST_MAILBOX),
				       TEST_UPDATE_ID" lookup read", i);
		/* the lock file doesn't stay behind */
		lock_path = t_strconcat(test_acl_cache_path(), ".lock", NULL);
		test_assert_idx(test_acl_read_file(lock_path) == NULL, i);
		test_acl_user_deinit();
	}
	test_end();
}

/* A concurrent writer holds the cache lock for longer than the timeout.
   The ACL update itself still succeeds, the cache keeps the old rights, and
   the owner's next read of the mailbox brings it up to date. flock() locks
   are per open file, so a second lock in this process really waits. */
static void test_acl_rights_cache_update_lock_timeout(void)
{
	struct acl_backend_vfile *backend;
	struct acl_object *aclobj;
	struct file_lock *lock;
	struct stat st;
	struct utimbuf ut;
	const char *lock_path, *acl_path, *error;
	bool created;
	int fd;

	test_begin("acl rights cache update lock timeout");
	test_acl_user_init(TEST_INPUT("lock_method=flock"));
	test_acl_mailbox_create(TEST_MAILBOX);
	test_acl_grant(TEST_MAILBOX, TEST_UPDATE_ID,
		       TEST_RIGHTS(MAIL_ACL_LOOKUP, MAIL_ACL_READ));
	backend = container_of(test_acl.backend, struct acl_backend_vfile,
			       backend);
	backend->rights_cache_lock_timeout_secs = 1;

	const struct file_create_settings lock_set = {
		.lock_timeout_secs = 1,
		.lock_settings = {
			.lock_method = FILE_LOCK_METHOD_FLOCK,
			.close_on_free = TRUE,
			.unlink_on_free = TRUE,
		},
	};
	lock_path = t_strconcat(test_acl_cache_path(), ".lock", NULL);
	fd = file_create_locked(lock_path, &lock_set, &lock, &created, &error);
	test_assert(fd != -1);

	/* the update times out on the cache, but the ACL file is written */
	aclobj = acl_object_init_from_name(test_acl.backend, TEST_MAILBOX);
	test_expect_error_string("file_create_locked(");
	test_assert(test_acl_do_update(aclobj, TEST_UPDATE_ID,
				       TEST_RIGHTS(MAIL_ACL_INSERT),
				       ACL_MODIFY_MODE_ADD,
				       ACL_MODIFY_MODE_ADD) == 0);
	test_expect_no_more_errors();
	acl_object_deinit(&aclobj);
	test_assert(strstr(test_acl_read_file(test_acl_local_path(TEST_MAILBOX)),
			   "i") != NULL);
	test_assert_strcmp(test_acl_cache_get(TEST_MAILBOX),
			   TEST_UPDATE_ID" lookup read");
	file_lock_free(&lock);

	/* The owner's next read of the mailbox repairs the cache, once the
	   ACL file's mtime differs from the cached entry's. Both changes
	   may have got the same mtime here, so push the mtime forward. */
	acl_path = test_acl_local_path(TEST_MAILBOX);
	if (stat(acl_path, &st) < 0)
		i_fatal("stat(%s) failed: %m", acl_path);
	ut.actime = st.st_atime;
	ut.modtime = st.st_mtime + 10;
	if (utime(acl_path, &ut) < 0)
		i_fatal("utime(%s) failed: %m", acl_path);
	aclobj = acl_object_init_from_name(test_acl.backend, TEST_MAILBOX);
	(void)test_acl_my_rights(aclobj);
	acl_object_deinit(&aclobj);
	test_assert_strcmp(test_acl_cache_get(TEST_MAILBOX),
			   TEST_UPDATE_ID" insert lookup read");

	test_acl_user_deinit();
	test_end();
}

static void test_acl_rights_cache_exact_match(void)
{
	test_begin("acl rights cache exact match");
	test_acl_user_init(NULL);
	test_acl_mailbox_create(TEST_MAILBOX);
	test_acl_grant(TEST_MAILBOX, TEST_UPDATE_ID,
		       TEST_RIGHTS(MAIL_ACL_LOOKUP, MAIL_ACL_READ));

	/* entries are literal mailbox names: a '*' matches nothing but
	   itself, unlike in the (deprecated) global ACL files */
	test_acl_write_file(test_acl_cache_path(),
			    "V1\n0\t-\tTe*\tanyone\tl\n");
	test_assert(acl_rights_cache_file_refresh(test_acl_cache_file()) == 1);

	test_assert_strcmp(test_acl_cache_get(TEST_MAILBOX), "");
	test_assert(!acl_rights_cache_file_have_any(test_acl_cache_file(),
						    TEST_MAILBOX, NULL));
	test_assert_strcmp(test_acl_cache_get("Te*"), "anyone lookup");
	test_assert(acl_rights_cache_file_have_any(test_acl_cache_file(),
						   "Te*", NULL));

	test_acl_user_deinit();
	test_end();
}

static void test_acl_rights_cache_update_isolated(void)
{
	const char *other_lines;

	test_begin("acl rights cache update leaves others alone");
	test_acl_user_init(NULL);
	test_acl_mailbox_create(TEST_MAILBOX);
	test_acl_mailbox_create(TEST_MAILBOX2);
	test_acl_grant(TEST_MAILBOX, TEST_UPDATE_ID,
		       TEST_RIGHTS(MAIL_ACL_LOOKUP, MAIL_ACL_READ));
	test_acl_grant(TEST_MAILBOX2, TEST_UPDATE_ID,
		       TEST_RIGHTS(MAIL_ACL_LOOKUP));

	other_lines = t_strdup(test_acl_cache_raw_lines(TEST_MAILBOX2));

	test_acl_grant(TEST_MAILBOX, TEST_UPDATE_ID,
		       TEST_RIGHTS(MAIL_ACL_INSERT));

	/* the other mailbox's lines are byte-identical */
	test_assert_strcmp(test_acl_cache_raw_lines(TEST_MAILBOX2),
			   other_lines);
	/* and the writer reads its own write without waiting for
	   acl_cache_ttl */
	test_assert_strcmp(test_acl_cache_get(TEST_MAILBOX),
			   TEST_UPDATE_ID" insert lookup read");

	test_acl_user_deinit();
	test_end();
}

static void test_acl_rights_cache_evict(void)
{
	struct acl_mailbox_list_context *ctx;
	const char *name;

	test_begin("acl rights cache evict");
	test_acl_user_init(NULL);
	test_acl_mailbox_create(TEST_MAILBOX);
	test_acl_mailbox_create(TEST_MAILBOX2);
	test_acl_grant(TEST_MAILBOX, TEST_UPDATE_ID,
		       TEST_RIGHTS(MAIL_ACL_LOOKUP, MAIL_ACL_READ));
	test_acl_grant(TEST_MAILBOX2, TEST_UPDATE_ID,
		       TEST_RIGHTS(MAIL_ACL_LOOKUP));

	acl_rights_cache_evict(test_acl.backend, TEST_MAILBOX, 0);
	test_assert_strcmp(test_acl_cache_get(TEST_MAILBOX), "");
	test_assert_strcmp(test_acl_cache_get(TEST_MAILBOX2),
			   TEST_UPDATE_ID" lookup");

	/* the iterated cache state must not change during an iteration */
	ctx = acl_backend_nonowner_lookups_iter_init(test_acl.backend);
	acl_rights_cache_evict(test_acl.backend, TEST_MAILBOX2, 0);
	while (acl_backend_nonowner_lookups_iter_next(ctx, &name)) ;
	test_assert(acl_backend_nonowner_lookups_iter_deinit(&ctx) == 1);
	test_assert_strcmp(test_acl_cache_get(TEST_MAILBOX2),
			   TEST_UPDATE_ID" lookup");

	test_acl_user_deinit();
	test_end();
}

static void test_acl_rights_cache_verify(void)
{
	struct acl_object *aclobj;
	struct stat st;
	struct utimbuf ut;
	const char *acl_path;

	test_begin("acl rights cache verify");
	test_acl_user_init(TEST_INPUT("acl_user="TEST_ACL_USER));
	test_acl_mailbox_create(TEST_MAILBOX);
	test_acl_grant(TEST_MAILBOX, TEST_UPDATE_ID,
		       TEST_RIGHTS(MAIL_ACL_LOOKUP, MAIL_ACL_READ));
	acl_path = test_acl_local_path(TEST_MAILBOX);

	/* change the ACL file without going through acl_object_update(),
	   like dsync does. Push the mtime forward - with the same mtime the
	   entry would look up-to-date. */
	test_acl_write_file(acl_path, TEST_UPDATE_ID" lrw\n");
	if (stat(acl_path, &st) < 0)
		i_fatal("stat(%s) failed: %m", acl_path);
	ut.actime = st.st_atime;
	ut.modtime = st.st_mtime + 10;
	if (utime(acl_path, &ut) < 0)
		i_fatal("utime(%s) failed: %m", acl_path);

	/* the next read of the ACL file resynchronizes the cache entry */
	aclobj = acl_object_init_from_name(test_acl.backend, TEST_MAILBOX);
	test_assert_strcmp(test_acl_my_rights(aclobj), "lookup read write");
	acl_object_deinit(&aclobj);
	test_assert_strcmp(test_acl_cache_get(TEST_MAILBOX),
			   TEST_UPDATE_ID" lookup read write");

	test_acl_user_deinit();
	test_end();
}

/* The cache entry has the ACL file's mtime with microseconds, so an entry
   that differs from the file only in them is rewritten. The entry is written
   by hand to differ from whatever the file's mtime is, so the filesystem
   needs no sub-second timestamps. */
static void test_acl_rights_cache_verify_usecs(void)
{
	struct acl_object *aclobj;
	struct stat st;
	const char *acl_path, *cache_path, *new_path, *line;
	unsigned int usecs;

	test_begin("acl rights cache verify within the same second");
	test_acl_user_init(TEST_INPUT("acl_user="TEST_ACL_USER,
				      "acl_cache_ttl=0"));
	test_acl_mailbox_create(TEST_MAILBOX);
	test_acl_grant(TEST_MAILBOX, TEST_UPDATE_ID,
		       TEST_RIGHTS(MAIL_ACL_LOOKUP, MAIL_ACL_READ));
	acl_path = test_acl_local_path(TEST_MAILBOX);

	/* the ACL file changes without an ACL update, and the entry's mtime
	   differs from the file's only in the microseconds. The cache is
	   replaced with rename() like its own writes do, so the new inode
	   tells that it changed: the size stays the same, and so does the
	   mtime on a filesystem without sub-second timestamps. */
	test_acl_write_file(acl_path, TEST_UPDATE_ID" lrw\n");
	if (stat(acl_path, &st) < 0)
		i_fatal("stat(%s) failed: %m", acl_path);
	usecs = ST_MTIME_NSEC(st) / 1000;
	line = test_acl_cache_raw_lines(TEST_MAILBOX);
	cache_path = test_acl_cache_path();
	new_path = t_strconcat(cache_path, ".new", NULL);
	test_acl_write_file(new_path,
		t_strdup_printf("V1\n%"PRIdTIME_T".%06u%s\n", st.st_mtime,
				(usecs + 1) % 1000000, strchr(line, '\t')));
	if (rename(new_path, cache_path) < 0)
		i_fatal("rename(%s, %s) failed: %m", new_path, cache_path);

	aclobj = acl_object_init_from_name(test_acl.backend, TEST_MAILBOX);
	(void)test_acl_my_rights(aclobj);
	acl_object_deinit(&aclobj);
	test_assert_strcmp(test_acl_cache_get(TEST_MAILBOX),
			   TEST_UPDATE_ID" lookup read write");
	line = test_acl_cache_raw_lines(TEST_MAILBOX);
	test_assert_strcmp(t_strsplit_tabescaped(line)[0],
			   t_strdup_printf("%"PRIdTIME_T".%06u", st.st_mtime,
					   usecs));

	test_acl_user_deinit();
	test_end();
}

static void test_acl_rights_cache_iter_fails_unwritable(void)
{
	struct acl_mailbox_list_context *ctx;
	const char *name, *root_dir;
	enum mailbox_list_path_type type;

	test_begin("acl rights cache iteration fails without a cache");
	if (geteuid() == 0) {
		/* chmod() doesn't stop root */
		test_end();
		return;
	}
	test_acl_user_init(NULL);
	test_acl_mailbox_create(TEST_MAILBOX);
	/* the mailbox has ACLs, but there is no cache file */
	test_acl_write_file(test_acl_local_path(TEST_MAILBOX),
			    TEST_UPDATE_ID" lr\n");
	i_unlink_if_exists(test_acl_cache_path());

	if (!acl_backend_get_root_dir(test_acl.backend, &root_dir, &type))
		i_fatal("acl_backend_get_root_dir() failed");
	if (chmod(root_dir, 0555) < 0)
		i_fatal("chmod(%s) failed: %m", root_dir);

	/* The rebuild can't create the cache file, so the nonowner mailboxes
	   are unknown. The iteration must fail instead of yielding an empty
	   result - an empty result would make the ACL lookup dict rebuild
	   remove the user's existing share entries. */
	ctx = acl_backend_nonowner_lookups_iter_init(test_acl.backend);
	test_assert(!acl_backend_nonowner_lookups_iter_next(ctx, &name));
	test_assert(acl_backend_nonowner_lookups_iter_deinit(&ctx) == -1);

	if (chmod(root_dir, 0755) < 0)
		i_fatal("chmod(%s) failed: %m", root_dir);

	test_acl_user_deinit();
	test_end();
}

static void test_acl_rights_cache_rebuild_abort(void)
{
	const char *cache_before;

	test_begin("acl rights cache rebuild abort keeps the old file");
	test_acl_user_init(NULL);
	test_acl_mailbox_create(TEST_MAILBOX);
	test_acl_mailbox_create(TEST_MAILBOX2);
	test_acl_grant(TEST_MAILBOX, TEST_UPDATE_ID,
		       TEST_RIGHTS(MAIL_ACL_LOOKUP, MAIL_ACL_READ));

	cache_before = t_strdup(test_acl_read_file(test_acl_cache_path()));
	test_assert(cache_before != NULL);

	/* a rebuild that fails to read an ACL file must not replace the
	   existing cache with a partial one */
	test_acl_write_file(test_acl_local_path(TEST_MAILBOX2),
			    "b0rken junk here\n");
	test_expect_error_string("ACL file");
	test_assert(acl_backend_nonowner_lookups_rebuild(
			test_acl.backend, FALSE) == -1);
	test_expect_no_more_errors();
	test_assert_strcmp(test_acl_read_file(test_acl_cache_path()),
			   cache_before);

	test_acl_user_deinit();
	test_end();
}

/* A rebuild keeps the cache entry of a mailbox whose ACL file isn't
   locally available. A mailbox that is local and has no ACL file anymore
   really has none, so the rebuild drops its entry like the read path. */
static void test_acl_rights_cache_rebuild_drops_local(void)
{
	test_begin("acl rights cache rebuild drops a local mailbox's entry");
	test_acl_user_init(NULL);
	test_acl_mailbox_create(TEST_MAILBOX);
	test_acl_mailbox_create(TEST_MAILBOX2);
	test_acl_grant(TEST_MAILBOX, TEST_UPDATE_ID,
		       TEST_RIGHTS(MAIL_ACL_LOOKUP, MAIL_ACL_READ));
	test_acl_grant(TEST_MAILBOX2, TEST_UPDATE_ID,
		       TEST_RIGHTS(MAIL_ACL_LOOKUP));

	/* the ACL file is removed without an ACL update */
	i_unlink(test_acl_local_path(TEST_MAILBOX));
	test_assert(acl_backend_nonowner_lookups_rebuild(
			test_acl.backend, FALSE) == 0);
	test_assert_strcmp(test_acl_cache_get(TEST_MAILBOX), "");
	test_assert_strcmp(test_acl_cache_get(TEST_MAILBOX2),
			   TEST_UPDATE_ID" lookup");
	test_assert_strcmp(test_acl_cache_iterate(), TEST_MAILBOX2);

	test_acl_user_deinit();
	test_end();
}

/* The first line names the format version. A file without it, or with a
   version this code doesn't know, is unusable as a whole. */
static void test_acl_rights_cache_version(void)
{
	static const struct {
		const char *content;
		const char *error;
	} tests[] = {
		{ "0\t-\t"TEST_MAILBOX"\tanyone\tl\n",
		  "Unsupported version line" },
		{ "V2\n0\t-\t"TEST_MAILBOX"\tanyone\tl\n",
		  "Unsupported version line" },
		{ "", "Missing version line" },
	};
	const char *cache_path, *cache;

	test_begin("acl rights cache version line");
	test_acl_user_init(NULL);
	test_acl_mailbox_create(TEST_MAILBOX);
	test_acl_grant(TEST_MAILBOX, TEST_UPDATE_ID,
		       TEST_RIGHTS(MAIL_ACL_LOOKUP, MAIL_ACL_READ));
	cache_path = test_acl_cache_path();

	for (unsigned int i = 0; i < N_ELEMENTS(tests); i++) {
		test_acl_write_file(cache_path, tests[i].content);
		test_expect_error_string(tests[i].error);
		test_assert_idx(acl_rights_cache_file_refresh(
					test_acl_cache_file()) == -1, i);
		test_expect_no_more_errors();
		test_assert_strcmp_idx(test_acl_cache_get(TEST_MAILBOX), "", i);
	}

	/* a rebuild replaces the unusable file, after failing to read it
	   under the lock once more */
	test_expect_error_string("Missing version line");
	test_assert(acl_backend_nonowner_lookups_rebuild(test_acl.backend,
							  FALSE) == 0);
	test_expect_no_more_errors();
	cache = test_acl_read_file(cache_path);
	test_assert(cache != NULL && str_begins_with(cache, "V1\n"));
	test_assert_strcmp(test_acl_cache_get(TEST_MAILBOX),
			   TEST_UPDATE_ID" lookup read");

	test_acl_user_deinit();
	test_end();
}

/* A mailbox has a single line. A second one means the file is corrupt. */
static void test_acl_rights_cache_duplicate_mailbox(void)
{
	test_begin("acl rights cache duplicate mailbox");
	test_acl_user_init(NULL);
	test_acl_mailbox_create(TEST_MAILBOX);
	test_acl_grant(TEST_MAILBOX, TEST_UPDATE_ID,
		       TEST_RIGHTS(MAIL_ACL_LOOKUP, MAIL_ACL_READ));

	test_acl_write_file(test_acl_cache_path(),
			    "V1\n"
			    "0\t-\t"TEST_MAILBOX"\tanyone\tl\n"
			    "0\t-\t"TEST_MAILBOX2"\tanyone\tl\n"
			    "0\t-\t"TEST_MAILBOX"\tanyone\tr\n");
	test_expect_error_string("Duplicate mailbox "TEST_MAILBOX);
	test_assert(acl_rights_cache_file_refresh(test_acl_cache_file()) == -1);
	test_expect_no_more_errors();
	test_assert_strcmp(test_acl_cache_get(TEST_MAILBOX2), "");

	test_acl_user_deinit();
	test_end();
}

/* Flags this version doesn't know stay with the mailbox's line through
   every rewrite of the file. */
static void test_acl_rights_cache_unknown_flags(void)
{
	test_begin("acl rights cache keeps unknown flags");
	test_acl_user_init(NULL);
	test_acl_mailbox_create(TEST_MAILBOX);
	test_acl_mailbox_create(TEST_MAILBOX2);
	test_acl_grant(TEST_MAILBOX, TEST_UPDATE_ID,
		       TEST_RIGHTS(MAIL_ACL_LOOKUP, MAIL_ACL_READ));
	test_acl_grant(TEST_MAILBOX2, TEST_UPDATE_ID,
		       TEST_RIGHTS(MAIL_ACL_LOOKUP));

	test_acl_write_file(test_acl_cache_path(),
			    "V1\n"
			    "0\txy\t"TEST_MAILBOX"\t"TEST_UPDATE_ID"\tlr\n"
			    "0\t-\t"TEST_MAILBOX2"\t"TEST_UPDATE_ID"\tl\n");
	test_assert(acl_rights_cache_file_refresh(test_acl_cache_file()) == 1);
	test_assert_strcmp(test_acl_cache_flags(TEST_MAILBOX), "xy");

	/* another mailbox's update rewrites the line as it is */
	test_acl_grant(TEST_MAILBOX2, TEST_UPDATE_ID,
		       TEST_RIGHTS(MAIL_ACL_INSERT));
	test_assert_strcmp(test_acl_cache_flags(TEST_MAILBOX), "xy");
	test_assert_strcmp(test_acl_cache_flags(TEST_MAILBOX2), "-");

	/* the mailbox's own update */
	test_acl_grant(TEST_MAILBOX, TEST_UPDATE_ID,
		       TEST_RIGHTS(MAIL_ACL_INSERT));
	test_assert_strcmp(test_acl_cache_flags(TEST_MAILBOX), "xy");
	test_assert_strcmp(test_acl_cache_get(TEST_MAILBOX),
			   TEST_UPDATE_ID" insert lookup read");

	/* a rebuild */
	test_assert(acl_backend_nonowner_lookups_rebuild(test_acl.backend,
							  FALSE) == 0);
	test_assert_strcmp(test_acl_cache_flags(TEST_MAILBOX), "xy");

	/* without rights the line stays for its flags */
	acl_rights_cache_evict(test_acl.backend, TEST_MAILBOX, 0);
	test_assert_strcmp(test_acl_cache_raw_lines(TEST_MAILBOX),
			   "0.000000\txy\t"TEST_MAILBOX);
	test_assert_strcmp(test_acl_cache_get(TEST_MAILBOX), "");

	test_acl_user_deinit();
	test_end();
}

/* The fields are tab-escaped, so any mailbox name fits on its line. */
static void test_acl_rights_cache_escaped_name(void)
{
	const char *cache_path, *cache;

	test_begin("acl rights cache escaped mailbox name");
	test_acl_user_init(NULL);
	test_acl_mailbox_create(TEST_MAILBOX);
	test_acl_grant(TEST_MAILBOX, TEST_UPDATE_ID,
		       TEST_RIGHTS(MAIL_ACL_LOOKUP, MAIL_ACL_READ));
	cache_path = test_acl_cache_path();

	/* a name with a TAB in it */
	test_acl_write_file(cache_path,
		t_strconcat(test_acl_read_file(cache_path),
			    "0\t-\tTab\001tBox\tanyone\tl\n", NULL));
	test_assert(acl_rights_cache_file_refresh(test_acl_cache_file()) == 1);
	test_assert_strcmp(test_acl_cache_get("Tab\tBox"), "anyone lookup");

	/* another mailbox's update writes the name escaped again */
	test_acl_grant(TEST_MAILBOX, TEST_UPDATE_ID,
		       TEST_RIGHTS(MAIL_ACL_INSERT));
	cache = test_acl_read_file(cache_path);
	test_assert(cache != NULL &&
		    strstr(cache, "\tTab\001tBox\tanyone\tl\n") != NULL);
	test_assert_strcmp(test_acl_cache_get("Tab\tBox"), "anyone lookup");

	test_acl_user_deinit();
	test_end();
}

/* The mailbox's maildir tmp/ directory. Opening a Maildir++ mailbox creates
   it again if it's missing. */
static const char *test_acl_mailbox_tmp_path(const char *name)
{
	const char *path;

	if (mailbox_list_get_path(test_acl.list, name,
				  MAILBOX_LIST_PATH_TYPE_MAILBOX, &path) <= 0)
		i_fatal("mailbox_list_get_path(%s) failed", name);
	return t_strconcat(path, "/tmp", NULL);
}

/* With a storage that has a mailbox's files locally only while the mailbox
   is open, a rebuild keeps the entry of a mailbox whose ACL file is missing
   or older than the entry, and trusts any other local ACL file. doveadm acl
   recalc opens every mailbox instead, and uses what their ACL files have
   then. */
static void test_acl_rights_cache_rebuild_cached_files(void)
{
	const char *acl_path, *tmp_path, *tmp_path2;
	struct stat st;
	struct utimbuf ut;

	test_begin("acl rights cache rebuild with cached files");
	test_acl_user_init(NULL);
	test_acl_storage_set_cached_files();
	test_acl_mailbox_create(TEST_MAILBOX);
	test_acl_mailbox_create(TEST_MAILBOX2);
	test_acl_grant(TEST_MAILBOX, TEST_UPDATE_ID,
		       TEST_RIGHTS(MAIL_ACL_LOOKUP, MAIL_ACL_READ));
	test_acl_grant(TEST_MAILBOX2, TEST_UPDATE_ID,
		       TEST_RIGHTS(MAIL_ACL_LOOKUP));

	/* an old copy of the ACL file */
	acl_path = test_acl_local_path(TEST_MAILBOX2);
	if (stat(acl_path, &st) < 0)
		i_fatal("stat(%s) failed: %m", acl_path);
	test_acl_write_file(acl_path, TEST_UPDATE_ID" lrw\n");
	ut.actime = st.st_atime;
	ut.modtime = st.st_mtime - 10;
	if (utime(acl_path, &ut) < 0)
		i_fatal("utime(%s) failed: %m", acl_path);
	/* an ACL file that isn't locally available */
	i_unlink(test_acl_local_path(TEST_MAILBOX));

	test_assert(acl_backend_nonowner_lookups_rebuild(test_acl.backend,
							  FALSE) == 0);
	test_assert_strcmp(test_acl_cache_get(TEST_MAILBOX),
			   TEST_UPDATE_ID" lookup read");
	test_assert_strcmp(test_acl_cache_get(TEST_MAILBOX2),
			   TEST_UPDATE_ID" lookup");

	/* doveadm acl recalc */
	test_assert(acl_backend_nonowner_lookups_rebuild(test_acl.backend,
							  TRUE) == 0);
	test_assert_strcmp(test_acl_cache_get(TEST_MAILBOX), "");
	test_assert_strcmp(test_acl_cache_get(TEST_MAILBOX2),
			   TEST_UPDATE_ID" lookup read write");

	/* The entry has the ACL file's mtime now. A rebuild trusts the file
	   and doesn't open the mailbox. */
	tmp_path2 = test_acl_mailbox_tmp_path(TEST_MAILBOX2);
	if (rmdir(tmp_path2) < 0)
		i_fatal("rmdir(%s) failed: %m", tmp_path2);
	test_assert(acl_backend_nonowner_lookups_rebuild(test_acl.backend,
							  FALSE) == 0);
	test_assert(stat(tmp_path2, &st) < 0 && errno == ENOENT);

	/* doveadm acl recalc opens it, and a mailbox whose local ACL file
	   has no entry as well */
	test_acl_write_file(test_acl_local_path(TEST_MAILBOX),
			    TEST_UPDATE_ID" lr\n");
	tmp_path = test_acl_mailbox_tmp_path(TEST_MAILBOX);
	if (rmdir(tmp_path) < 0)
		i_fatal("rmdir(%s) failed: %m", tmp_path);
	test_assert(acl_backend_nonowner_lookups_rebuild(test_acl.backend,
							  TRUE) == 0);
	test_assert(stat(tmp_path, &st) == 0);
	test_assert(stat(tmp_path2, &st) == 0);
	test_assert_strcmp(test_acl_cache_get(TEST_MAILBOX),
			   TEST_UPDATE_ID" lookup read");
	test_assert_strcmp(test_acl_cache_get(TEST_MAILBOX2),
			   TEST_UPDATE_ID" lookup read write");

	test_acl_user_deinit();
	test_end();
}

/* dovecot-acl-list next to the cache means that a version without the
   rights cache was used, and it may have changed the ACL files on another
   server. With cached files the rebuild then opens the mailboxes that have
   a cache entry or that the list names, also when their local ACL file is
   as new as the entry. A mailbox with neither keeps using its local ACL
   file. */
static void test_acl_rights_cache_rebuild_stale_cached(void)
{
	const char *root_dir, *list_path, *tmp_path, *tmp_path2, *tmp_path3;
	enum mailbox_list_path_type type;
	struct stat st;

	test_begin("acl rights cache rebuild for dovecot-acl-list next to the cache");
	test_acl_user_init(NULL);
	test_acl_storage_set_cached_files();
	test_acl_mailbox_create(TEST_MAILBOX);
	test_acl_mailbox_create(TEST_MAILBOX2);
	test_acl_mailbox_create(TEST_MAILBOX_DIGITS);
	test_acl_grant(TEST_MAILBOX, TEST_UPDATE_ID,
		       TEST_RIGHTS(MAIL_ACL_LOOKUP, MAIL_ACL_READ));
	test_assert(test_acl_cache_path() != NULL &&
		    stat(test_acl_cache_path(), &st) == 0);

	/* ACL files written by the version without the rights cache. The
	   list names only TEST_MAILBOX2. */
	test_acl_write_file(test_acl_local_path(TEST_MAILBOX2),
			    TEST_UPDATE_ID" lr\n");
	test_acl_write_file(test_acl_local_path(TEST_MAILBOX_DIGITS),
			    TEST_UPDATE_ID" lr\n");
	if (!acl_backend_get_root_dir(test_acl.backend, &root_dir, &type))
		i_fatal("acl_backend_get_root_dir() failed");
	list_path = t_strconcat(root_dir, "/dovecot-acl-list", NULL);
	test_acl_write_file(list_path, "0 "TEST_MAILBOX2"\n");

	tmp_path = test_acl_mailbox_tmp_path(TEST_MAILBOX);
	tmp_path2 = test_acl_mailbox_tmp_path(TEST_MAILBOX2);
	tmp_path3 = test_acl_mailbox_tmp_path(TEST_MAILBOX_DIGITS);
	if (rmdir(tmp_path) < 0)
		i_fatal("rmdir(%s) failed: %m", tmp_path);
	if (rmdir(tmp_path2) < 0)
		i_fatal("rmdir(%s) failed: %m", tmp_path2);
	if (rmdir(tmp_path3) < 0)
		i_fatal("rmdir(%s) failed: %m", tmp_path3);

	test_assert(acl_backend_nonowner_lookups_rebuild(test_acl.backend,
							  FALSE) == 0);
	/* the cached mailbox and the listed one were opened */
	test_assert(stat(tmp_path, &st) == 0);
	test_assert(stat(tmp_path2, &st) == 0);
	test_assert(stat(tmp_path3, &st) < 0 && errno == ENOENT);
	test_assert_strcmp(test_acl_cache_get(TEST_MAILBOX),
			   TEST_UPDATE_ID" lookup read");
	test_assert_strcmp(test_acl_cache_get(TEST_MAILBOX2),
			   TEST_UPDATE_ID" lookup read");
	test_assert_strcmp(test_acl_cache_get(TEST_MAILBOX_DIGITS),
			   TEST_UPDATE_ID" lookup read");
	test_assert(stat(list_path, &st) < 0 && errno == ENOENT);

	test_acl_user_deinit();
	test_end();
}

/* The rebuild reads the ACL files like the normal read path does, also
   lines that start with whitespace. */
static void test_acl_rights_cache_rebuild_lwsp(void)
{
	test_begin("acl rights cache rebuild reads indented ACL lines");
	test_acl_user_init(NULL);
	test_acl_mailbox_create(TEST_MAILBOX);
	test_acl_write_file(test_acl_local_path(TEST_MAILBOX),
			    "  "TEST_UPDATE_ID" lr\n\t# a comment\n");

	test_assert(acl_backend_nonowner_lookups_rebuild(test_acl.backend,
							  FALSE) == 0);
	test_assert_strcmp(test_acl_cache_get(TEST_MAILBOX),
			   TEST_UPDATE_ID" lookup read");

	test_acl_user_deinit();
	test_end();
}

/* An identifier's rights can be spread over several lines of an ACL file.
   The cache keeps them merged, and removing the identifier removes all of
   its rights. */
static void test_acl_rights_cache_duplicate_ids(void)
{
	struct acl_object *aclobj;
	const char *line, *mtime;

	test_begin("acl rights cache merges duplicate identifiers");
	test_acl_user_init(NULL);
	test_acl_mailbox_create(TEST_MAILBOX);
	test_acl_write_file(test_acl_local_path(TEST_MAILBOX),
			    TEST_UPDATE_ID" l\n"TEST_UPDATE_ID" r\n");

	test_assert(acl_backend_nonowner_lookups_rebuild(test_acl.backend,
							  FALSE) == 0);
	test_assert_strcmp(test_acl_cache_get(TEST_MAILBOX),
			   TEST_UPDATE_ID" lookup read");
	line = test_acl_cache_raw_lines(TEST_MAILBOX);
	test_assert(str_array_length(t_strsplit_tabescaped(line)) == 3 + 2);

	/* the same entry as it would be without the merging */
	mtime = t_strsplit_tabescaped(line)[0];
	test_acl_write_file(test_acl_cache_path(),
		t_strdup_printf("V1\n%s\t-\t"TEST_MAILBOX"\t"TEST_UPDATE_ID
				"\tl\t"TEST_UPDATE_ID"\tr\n", mtime));
	test_assert(acl_rights_cache_file_refresh(test_acl_cache_file()) == 1);

	aclobj = acl_object_init_from_name(test_acl.backend, TEST_MAILBOX);
	test_assert(test_acl_do_update(aclobj, TEST_UPDATE_ID, NULL,
				       ACL_MODIFY_MODE_CLEAR,
				       ACL_MODIFY_MODE_CLEAR) == 0);
	acl_object_deinit(&aclobj);
	test_assert_strcmp(test_acl_cache_raw_lines(TEST_MAILBOX), "");

	test_acl_user_deinit();
	test_end();
}

/* The marker follows the configured ACLs, which can change while a
   mailbox's ACL file stays the same. */
static void test_acl_rights_cache_marker_follows_config(void)
{
	struct acl_object *aclobj;
	const char *cache_path, *cache, *p;
	const char *with_marker = "\tm\t"TEST_MAILBOX"\t";

	test_begin("acl rights cache marker follows the configured ACLs");
	/* acl anyone { rights = lr } */
	test_acl_user_init(TEST_INPUT("acl_cache_ttl=0", "acl+=anyone",
				      "acl/anyone/acl_rights=lr"));
	test_acl_mailbox_create(TEST_MAILBOX);
	test_acl_grant(TEST_MAILBOX, TEST_UPDATE_ID,
		       TEST_RIGHTS(MAIL_ACL_READ));
	test_assert(test_acl_cache_has_marker(TEST_MAILBOX));

	/* the entry as it was written before the acl setting existed */
	cache_path = test_acl_cache_path();
	cache = test_acl_read_file(cache_path);
	p = cache == NULL ? NULL : strstr(cache, with_marker);
	test_assert(p != NULL);
	if (p != NULL) {
		test_acl_write_file(cache_path,
			t_strconcat(t_strdup_until(cache, p),
				    "\t--\t"TEST_MAILBOX"\t",
				    p + strlen(with_marker), NULL));
	}
	test_assert(!test_acl_cache_has_marker(TEST_MAILBOX));

	/* the next read of the unchanged ACL file brings the marker back */
	aclobj = acl_object_init_from_name(test_acl.backend, TEST_MAILBOX);
	(void)test_acl_my_rights(aclobj);
	acl_object_deinit(&aclobj);
	test_assert(test_acl_cache_has_marker(TEST_MAILBOX));
	test_assert_strcmp(test_acl_cache_get(TEST_MAILBOX),
			   TEST_UPDATE_ID" read");

	test_acl_user_deinit();
	test_end();
}

/* All users write a public namespace's cache, and their configured ACLs may
   differ. Its marker doesn't follow them: a new entry gets none, and the
   marker an entry has is kept. */
static void test_acl_rights_cache_marker_public(void)
{
	struct acl_object *aclobj;

	test_begin("acl rights cache marker in a public namespace");
	/* acl anyone { rights = lr } */
	test_acl_user_init(TEST_INPUT("namespace/inbox/type=public",
				      "acl_cache_ttl=0", "acl+=anyone",
				      "acl/anyone/acl_rights=lr"));
	test_acl_mailbox_create(TEST_MAILBOX);
	test_acl_write_file(test_acl_local_path(TEST_MAILBOX),
			    TEST_UPDATE_ID" r\n");
	/* the read creates the cache with a rebuild */
	aclobj = acl_object_init_from_name(test_acl.backend, TEST_MAILBOX);
	(void)test_acl_my_rights(aclobj);
	acl_object_deinit(&aclobj);
	test_assert_strcmp(test_acl_cache_get(TEST_MAILBOX),
			   TEST_UPDATE_ID" read");
	test_assert(!test_acl_cache_has_marker(TEST_MAILBOX));
	test_acl_user_deinit();

	/* no acl setting, the entry is older than the ACL file */
	test_acl_user_init(TEST_INPUT("namespace/inbox/type=public",
				      "acl_cache_ttl=0"));
	test_acl_mailbox_create(TEST_MAILBOX);
	test_acl_write_file(test_acl_local_path(TEST_MAILBOX),
			    TEST_UPDATE_ID" r\n");
	test_acl_write_file(test_acl_cache_path(),
			    "V1\n0\tm\t"TEST_MAILBOX"\n");
	aclobj = acl_object_init_from_name(test_acl.backend, TEST_MAILBOX);
	(void)test_acl_my_rights(aclobj);
	acl_object_deinit(&aclobj);
	test_assert_strcmp(test_acl_cache_get(TEST_MAILBOX),
			   TEST_UPDATE_ID" read");
	test_assert(test_acl_cache_has_marker(TEST_MAILBOX));
	test_assert(acl_backend_nonowner_lookups_rebuild(test_acl.backend,
							 FALSE) == 0);
	test_assert(test_acl_cache_has_marker(TEST_MAILBOX));

	test_acl_user_deinit();
	test_end();
}

/* Neither the cache nor its .tmp file is followed if it is a symlink. */
static void test_acl_rights_cache_deleted_file(void)
{
	struct timeval mtime;

	test_begin("acl rights cache forgets a deleted cache file");
	test_acl_user_init(NULL);
	test_acl_mailbox_create(TEST_MAILBOX);

	test_acl_write_file(test_acl_cache_path(),
			    "V1\n1.000000\t-\t"TEST_MAILBOX"\tanyone\tl\n");
	test_assert(acl_rights_cache_file_refresh(test_acl_cache_file()) == 1);
	test_assert(acl_rights_cache_file_have_any(test_acl_cache_file(),
						   TEST_MAILBOX, NULL));

	/* the entries loaded from the file must not be served after it's
	   gone */
	i_unlink(test_acl_cache_path());
	test_assert(acl_rights_cache_file_refresh(test_acl_cache_file()) == 0);
	test_assert(!acl_rights_cache_file_have_any(test_acl_cache_file(),
						    TEST_MAILBOX, NULL));
	test_assert(!acl_rights_cache_file_get_mtime(test_acl_cache_file(),
						     TEST_MAILBOX, &mtime));
	test_assert_strcmp(test_acl_cache_get(TEST_MAILBOX), "");

	test_acl_user_deinit();
	test_end();
}

static void test_acl_rights_cache_symlinks(void)
{
	struct acl_object *aclobj;
	const char *cache_path, *tmp_path, *target_path;

	test_begin("acl rights cache doesn't follow symlinks");
	test_acl_user_init(NULL);
	test_acl_mailbox_create(TEST_MAILBOX);
	test_acl_grant(TEST_MAILBOX, TEST_UPDATE_ID,
		       TEST_RIGHTS(MAIL_ACL_LOOKUP, MAIL_ACL_READ));
	cache_path = test_acl_cache_path();
	tmp_path = t_strconcat(cache_path, ".tmp", NULL);
	target_path = t_strconcat(cache_path, ".target", NULL);

	/* a symlink as the .tmp file: the cache update fails, the ACL update
	   doesn't, and the link's target isn't truncated */
	test_acl_write_file(target_path, "victim\n");
	if (symlink(target_path, tmp_path) < 0)
		i_fatal("symlink(%s, %s) failed: %m", target_path, tmp_path);
	aclobj = acl_object_init_from_name(test_acl.backend, TEST_MAILBOX);
	test_expect_error_string(".tmp, O_CREAT) failed");
	test_assert(test_acl_do_update(aclobj, TEST_UPDATE_ID,
				       TEST_RIGHTS(MAIL_ACL_INSERT),
				       ACL_MODIFY_MODE_ADD,
				       ACL_MODIFY_MODE_ADD) == 0);
	test_expect_no_more_errors();
	acl_object_deinit(&aclobj);
	test_assert_strcmp(test_acl_read_file(target_path), "victim\n");
	i_unlink(tmp_path);

	/* a symlink as the cache file: it isn't read */
	test_acl_write_file(target_path, test_acl_read_file(cache_path));
	i_unlink(cache_path);
	if (symlink(target_path, cache_path) < 0)
		i_fatal("symlink(%s, %s) failed: %m", target_path, cache_path);
	test_expect_error_string("Couldn't read ACL rights cache");
	test_assert(acl_rights_cache_file_refresh(test_acl_cache_file()) == -1);
	test_expect_no_more_errors();
	i_unlink(cache_path);

	test_acl_user_deinit();
	test_end();
}

int main(int argc, char **argv)
{
	static void (*const test_functions[])(void) = {
		test_acl_rights_cache_format,
		test_acl_rights_cache_version,
		test_acl_rights_cache_duplicate_mailbox,
		test_acl_rights_cache_unknown_flags,
		test_acl_rights_cache_escaped_name,
		test_acl_rights_cache_default_acl,
		test_acl_rights_cache_markers,
		test_acl_rights_cache_marker_with_file_rights,
		test_acl_rights_cache_partial_parse,
		test_acl_rights_cache_reparse_after_failure,
		test_acl_rights_cache_lock_methods,
		test_acl_rights_cache_update_lock_timeout,
		test_acl_rights_cache_exact_match,
		test_acl_rights_cache_deleted_file,
		test_acl_rights_cache_update_isolated,
		test_acl_rights_cache_evict,
		test_acl_rights_cache_verify,
		test_acl_rights_cache_verify_usecs,
		test_acl_rights_cache_iter_fails_unwritable,
		test_acl_rights_cache_rebuild_abort,
		test_acl_rights_cache_rebuild_drops_local,
		test_acl_rights_cache_rebuild_cached_files,
		test_acl_rights_cache_rebuild_stale_cached,
		test_acl_rights_cache_rebuild_lwsp,
		test_acl_rights_cache_duplicate_ids,
		test_acl_rights_cache_marker_follows_config,
		test_acl_rights_cache_marker_public,
		test_acl_rights_cache_symlinks,
		NULL
	};
	int ret;

	test_acl_common_init("test-acl-rights-cache", &argc, &argv);
	ret = test_run(test_functions);
	test_acl_common_deinit();
	return ret;
}
