/* Copyright (c) Dovecot authors, see top-level COPYING file */

/* Tests for the vfile ACL backend's read path: parsing dovecot-acl files,
   applying them to the calling user, and the name-keyed validity cache. */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "test-common.h"
#include "mail-storage.h"
#include "mailbox-list.h"
#include "acl-cache.h"
#include "acl-storage.h"
#include "acl-plugin.h"
#include "acl-backend-vfile.h"
#include "acl-rights-cache.h"
#include "test-acl-common.h"

#include <unistd.h>
#include <utime.h>
#include <sys/stat.h>

#define TEST_MAILBOX "Test"
#define TEST_CHILD_MAILBOX "Test/Child"
#define TEST_OTHER_USER "other@example.com"

/* all_mailbox_rights[] in declaration order, which is the order that
   test_acl_my_rights() returns them in */
#define TEST_ALL_RIGHTS \
	"lookup read write write-seen write-deleted insert post expunge " \
	"create delete admin"

/* NULL-terminated userdb field list */
#define TEST_INPUT(...) ((const char *const []){ __VA_ARGS__, NULL })
#define TEST_INPUT_READER TEST_INPUT("acl_user="TEST_ACL_USER)

static const char *test_acl_setup(const char *const *extra_input,
				  const char *acl_content)
{
	const char *path;

	test_acl_user_init(extra_input);
	test_acl_mailbox_create(TEST_MAILBOX);

	path = test_acl_local_path(TEST_MAILBOX);
	i_assert(path != NULL);
	if (acl_content != NULL)
		test_acl_write_file(path, acl_content);
	return path;
}

static void test_acl_vfile_owner_defaults(void)
{
	struct acl_object *aclobj;

	test_begin("acl vfile owner defaults");
	/* without acl_user the ACL user is the storage owner */
	(void)test_acl_setup(NULL, NULL);
	test_assert(acl_backend_user_is_owner(test_acl.backend));

	aclobj = acl_object_init_from_name(test_acl.backend, TEST_MAILBOX);
	/* no ACL file: the owner still gets everything */
	test_assert_strcmp(test_acl_my_rights(aclobj), TEST_ALL_RIGHTS);
	test_assert_strcmp(test_acl_list(aclobj), "");
	acl_object_deinit(&aclobj);

	test_acl_user_deinit();
	test_end();
}

static void test_acl_vfile_nonowner_defaults(void)
{
	struct acl_object *aclobj;
	unsigned int lookup_idx;

	test_begin("acl vfile non-owner defaults");
	(void)test_acl_setup(TEST_INPUT_READER, NULL);
	test_assert(!acl_backend_user_is_owner(test_acl.backend));

	lookup_idx = acl_backend_lookup_right(test_acl.backend,
					      MAIL_ACL_LOOKUP);
	aclobj = acl_object_init_from_name(test_acl.backend, TEST_MAILBOX);
	/* no ACL file: a non-owner gets nothing */
	test_assert_strcmp(test_acl_my_rights(aclobj), "");
	test_assert_strcmp(test_acl_list(aclobj), "");
	test_assert(acl_object_have_right(aclobj, lookup_idx) == 0);
	acl_object_deinit(&aclobj);

	test_acl_user_deinit();
	test_end();
}

static void test_acl_vfile_local_file(void)
{
	struct acl_object *aclobj;
	unsigned int read_idx, admin_idx;

	test_begin("acl vfile local file");
	(void)test_acl_setup(TEST_INPUT_READER,
			     "user="TEST_ACL_USER" lr\n"
			     "user="TEST_OTHER_USER" a\n");

	read_idx = acl_backend_lookup_right(test_acl.backend, MAIL_ACL_READ);
	admin_idx = acl_backend_lookup_right(test_acl.backend, MAIL_ACL_ADMIN);
	aclobj = acl_object_init_from_name(test_acl.backend, TEST_MAILBOX);

	test_assert_strcmp(test_acl_my_rights(aclobj), "lookup read");
	test_assert(acl_object_have_right(aclobj, read_idx) == 1);
	test_assert(acl_object_have_right(aclobj, admin_idx) == 0);
	/* listing returns every identifier, sorted by id type and name */
	test_assert_strcmp(test_acl_list(aclobj),
			   "user="TEST_OTHER_USER" admin, "
			   "user="TEST_ACL_USER" lookup read");
	acl_object_deinit(&aclobj);

	test_acl_user_deinit();
	test_end();
}

static void test_acl_vfile_comments(void)
{
	struct acl_object *aclobj;

	test_begin("acl vfile comments and empty lines");
	(void)test_acl_setup(TEST_INPUT_READER,
			     "# a comment\n"
			     "\n"
			     "user="TEST_ACL_USER" lr\n"
			     "# another comment\n");

	aclobj = acl_object_init_from_name(test_acl.backend, TEST_MAILBOX);
	test_assert_strcmp(test_acl_my_rights(aclobj), "lookup read");
	test_assert_strcmp(test_acl_list(aclobj),
			   "user="TEST_ACL_USER" lookup read");
	acl_object_deinit(&aclobj);

	test_acl_user_deinit();
	test_end();
}

static void test_acl_vfile_negative_rights(void)
{
	struct acl_object *aclobj;
	unsigned int write_idx;

	test_begin("acl vfile negative rights");
	(void)test_acl_setup(TEST_INPUT_READER,
			     "user="TEST_ACL_USER" lrwi\n"
			     "-user="TEST_ACL_USER" w\n");

	write_idx = acl_backend_lookup_right(test_acl.backend, MAIL_ACL_WRITE);
	aclobj = acl_object_init_from_name(test_acl.backend, TEST_MAILBOX);

	/* the negative entry overrides the positive one */
	test_assert_strcmp(test_acl_my_rights(aclobj), "lookup read insert");
	test_assert(acl_object_have_right(aclobj, write_idx) == 0);
	/* both are merged into a single listed identifier */
	test_assert_strcmp(test_acl_list(aclobj),
			   "user="TEST_ACL_USER" insert lookup read write "
			   "-write");
	acl_object_deinit(&aclobj);

	test_acl_user_deinit();
	test_end();
}

static void test_acl_vfile_id_precedence(void)
{
	struct acl_object *aclobj;

	test_begin("acl vfile identifier precedence");
	/* a more specific identifier replaces - not merges with - the rights
	   of a less specific one */
	(void)test_acl_setup(TEST_INPUT_READER,
			     "anyone l\n"
			     "authenticated r\n"
			     "user="TEST_ACL_USER" i\n");

	aclobj = acl_object_init_from_name(test_acl.backend, TEST_MAILBOX);
	test_assert_strcmp(test_acl_my_rights(aclobj), "insert");
	acl_object_deinit(&aclobj);
	test_acl_user_deinit();

	/* without the user entry, "authenticated" wins over "anyone" */
	(void)test_acl_setup(TEST_INPUT_READER,
			     "anyone l\n"
			     "authenticated r\n");
	aclobj = acl_object_init_from_name(test_acl.backend, TEST_MAILBOX);
	test_assert_strcmp(test_acl_my_rights(aclobj), "read");
	acl_object_deinit(&aclobj);
	test_acl_user_deinit();

	/* and "anyone" alone applies to everybody */
	(void)test_acl_setup(TEST_INPUT_READER, "anyone l\n");
	aclobj = acl_object_init_from_name(test_acl.backend, TEST_MAILBOX);
	test_assert_strcmp(test_acl_my_rights(aclobj), "lookup");
	acl_object_deinit(&aclobj);
	test_acl_user_deinit();

	test_end();
}

static void test_acl_vfile_owner_entry(void)
{
	struct acl_object *aclobj;

	test_begin("acl vfile owner entry");
	/* an explicit owner entry replaces the implicit all-rights default,
	   and entries for less specific identifiers are skipped entirely */
	(void)test_acl_setup(NULL,
			     "anyone a\n"
			     "owner lr\n");

	aclobj = acl_object_init_from_name(test_acl.backend, TEST_MAILBOX);
	test_assert_strcmp(test_acl_my_rights(aclobj), "lookup read");
	acl_object_deinit(&aclobj);

	test_acl_user_deinit();
	test_end();
}

static void test_acl_vfile_fresh_object_cache(void)
{
	struct acl_object *aclobj, *aclobj2;
	const struct acl_rights *rights;
	unsigned int read_idx;

	test_begin("acl vfile fresh object with warm name-cache");
	(void)test_acl_setup(TEST_INPUT_READER,
			     "user="TEST_ACL_USER" lr\n");

	read_idx = acl_backend_lookup_right(test_acl.backend, MAIL_ACL_READ);
	aclobj = acl_object_init_from_name(test_acl.backend, TEST_MAILBOX);
	test_assert_strcmp(test_acl_my_rights(aclobj), "lookup read");

	/* the first read warmed the backend's name-keyed validity cache */
	test_assert(acl_cache_get_validity(test_acl.backend->cache,
					   TEST_MAILBOX) != NULL);

	/* A second, freshly allocated object for the same name shares that
	   cache, but its own rights array was never filled in. It must still
	   perform a real read - consumers that walk acl_object.rights
	   directly would otherwise see an empty ACL. */
	aclobj2 = acl_object_init_from_name(test_acl.backend, TEST_MAILBOX);
	test_assert(acl_object_have_right(aclobj2, read_idx) == 1);
	test_assert(array_is_created(&aclobj2->rights));
	if (array_is_created(&aclobj2->rights) &&
	    array_count(&aclobj2->rights) == 1) {
		rights = array_idx(&aclobj2->rights, 0);
		test_assert(rights->id_type == ACL_ID_USER);
		test_assert_strcmp(rights->identifier, TEST_ACL_USER);
	} else {
		test_assert(FALSE);
	}

	acl_object_deinit(&aclobj);
	acl_object_deinit(&aclobj2);
	test_acl_user_deinit();
	test_end();
}

static void test_acl_vfile_cache_ttl(void)
{
	struct acl_object *aclobj;
	const char *path;

	test_begin("acl vfile cache ttl");
	path = test_acl_setup(TEST_INPUT("acl_cache_ttl=30s",
					 "acl_user="TEST_ACL_USER),
			      "user="TEST_ACL_USER" lr\n");

	aclobj = acl_object_init_from_name(test_acl.backend, TEST_MAILBOX);
	test_assert_strcmp(test_acl_my_rights(aclobj), "lookup read");

	/* A read stores a fresh validity record, whose last_check is zero,
	   so the next lookup still stat()s the file. Only once that lookup
	   has found the file unchanged does the validity hold for
	   acl_cache_ttl. */
	test_assert_strcmp(test_acl_my_rights(aclobj), "lookup read");

	/* from here on the file isn't looked at again */
	test_acl_write_file(path, "user="TEST_ACL_USER" lrwi\n");
	test_assert_strcmp(test_acl_my_rights(aclobj), "lookup read");

	/* flushing the name-cache forces a re-read */
	acl_cache_flush(test_acl.backend->cache, TEST_MAILBOX);
	test_assert_strcmp(test_acl_my_rights(aclobj),
			   "lookup read write insert");

	acl_object_deinit(&aclobj);
	test_acl_user_deinit();
	test_end();
}

static void test_acl_vfile_file_changed(void)
{
	struct acl_object *aclobj;
	const char *path;

	test_begin("acl vfile file changed");
	/* with the cache disabled every lookup re-checks the file */
	path = test_acl_setup(TEST_INPUT("acl_cache_ttl=0",
					 "acl_user="TEST_ACL_USER),
			      "user="TEST_ACL_USER" lr\n");

	aclobj = acl_object_init_from_name(test_acl.backend, TEST_MAILBOX);
	test_assert_strcmp(test_acl_my_rights(aclobj), "lookup read");

	/* the size differs, so the change is seen even within the same
	   second as the previous read */
	test_acl_write_file(path, "user="TEST_ACL_USER" lrwi\n");
	test_assert_strcmp(test_acl_my_rights(aclobj),
			   "lookup read write insert");

	/* and so is the file disappearing */
	i_unlink(path);
	test_assert_strcmp(test_acl_my_rights(aclobj), "");

	acl_object_deinit(&aclobj);
	test_acl_user_deinit();
	test_end();
}

static void test_acl_vfile_last_changed(void)
{
	struct acl_object *aclobj;
	const char *path;
	struct stat st;
	time_t last_changed;

	test_begin("acl vfile last changed");
	path = test_acl_setup(TEST_INPUT_READER,
			      "user="TEST_ACL_USER" lr\n");
	if (stat(path, &st) < 0)
		i_fatal("stat(%s) failed: %m", path);

	aclobj = acl_object_init_from_name(test_acl.backend, TEST_MAILBOX);
	test_assert(acl_object_last_changed(aclobj, &last_changed) == 0);
	test_assert_cmp(last_changed, ==, st.st_mtime);
	acl_object_deinit(&aclobj);
	test_acl_user_deinit();

	/* no ACL file means no change timestamp */
	(void)test_acl_setup(TEST_INPUT_READER, NULL);
	aclobj = acl_object_init_from_name(test_acl.backend, TEST_MAILBOX);
	test_assert(acl_object_last_changed(aclobj, &last_changed) == 0);
	test_assert_cmp(last_changed, ==, 0);
	acl_object_deinit(&aclobj);
	test_acl_user_deinit();

	test_end();
}

static void test_acl_vfile_parse_error(void)
{
	struct acl_object *aclobj;

	test_begin("acl vfile parse error");
	(void)test_acl_setup(TEST_INPUT_READER,
			     "user="TEST_ACL_USER" lr\n"
			     "bogus\n");

	aclobj = acl_object_init_from_name(test_acl.backend, TEST_MAILBOX);
	/* an unparseable line makes the whole file unusable rather than
	   silently granting the rights of the lines before it. The error is
	   logged twice: the first ACL read also tries to create the rights
	   cache, and that rebuild reads every mailbox's ACL file. */
	test_expect_error_string_n_times("line 2: Unknown ID 'bogus'", 2);
	test_assert_strcmp(test_acl_my_rights(aclobj), "<error>");
	test_expect_no_more_errors();
	acl_object_deinit(&aclobj);

	test_acl_user_deinit();
	test_end();
}

static void test_acl_vfile_defaults_from_inbox(void)
{
	struct acl_object *aclobj;
	const char *inbox_path;

	test_begin("acl vfile defaults from inbox");
	(void)test_acl_setup(TEST_INPUT("acl_defaults_from_inbox=yes",
					"acl_user="TEST_ACL_USER), NULL);

	inbox_path = test_acl_local_path("INBOX");
	test_assert(inbox_path != NULL);
	if (inbox_path != NULL)
		test_acl_write_file(inbox_path, "user="TEST_ACL_USER" lr\n");

	/* the mailbox has no ACL file of its own, so INBOX's ACLs are used
	   as the default */
	aclobj = acl_object_init_from_name(test_acl.backend, TEST_MAILBOX);
	test_assert_strcmp(test_acl_my_rights(aclobj), "lookup read");
	acl_object_deinit(&aclobj);

	test_acl_user_deinit();
	test_end();
}

static void test_acl_vfile_config_rights(void)
{
	struct acl_object *aclobj;

	test_begin("acl vfile configured rights");
	/* The configuration has "acl anyone { rights = lr }" and the
	   mailbox's dovecot-acl file has "anyone lrw". */
	(void)test_acl_setup(TEST_INPUT("acl+=anyone",
					"acl/anyone/acl_rights=lr"),
			     "anyone lrw\n");

	aclobj = acl_object_init_from_name(test_acl.backend, TEST_MAILBOX);
	/* Both entries are listed. The configured one is global, so the two
	   aren't merged even though the identifier is the same. */
	test_assert_strcmp(test_acl_list(aclobj),
			   "anyone lookup read write, "
			   "anyone lookup read (global)");
	/* The configured entry overrides the file's entry. Since it's
	   global, it applies also to the mailbox owner, who would otherwise
	   have all rights. */
	test_assert_strcmp(test_acl_my_rights(aclobj), "lookup read");
	acl_object_deinit(&aclobj);
	test_acl_user_deinit();

	/* The configured entry overrides the file's entry also for a
	   non-owner user: "acl authenticated { rights = lr }" configured,
	   "authenticated w" in the file. */
	(void)test_acl_setup(TEST_INPUT("acl_user="TEST_ACL_USER,
					"acl+=authenticated",
					"acl/authenticated/acl_rights=lr"),
			     "authenticated w\n");

	aclobj = acl_object_init_from_name(test_acl.backend, TEST_MAILBOX);
	test_assert_strcmp(test_acl_my_rights(aclobj), "lookup read");
	acl_object_deinit(&aclobj);
	test_acl_user_deinit();

	/* The first matching global entry resets the negative rights from
	   the file: "acl anyone { rights = lrw }" configured,
	   "authenticated lrw" and "-authenticated w" in the file. */
	(void)test_acl_setup(TEST_INPUT("acl_user="TEST_ACL_USER,
					"acl+=anyone",
					"acl/anyone/acl_rights=lrw"),
			     "authenticated lrw\n-authenticated w\n");

	aclobj = acl_object_init_from_name(test_acl.backend, TEST_MAILBOX);
	test_assert_strcmp(test_acl_my_rights(aclobj),
			   "lookup read write");
	acl_object_deinit(&aclobj);
	test_acl_user_deinit();
	test_end();
}

static void test_acl_vfile_parent(void)
{
	struct acl_object *aclobj;
	const char *parent_name, *child_name, *parent_path;

	test_begin("acl vfile parent object");
	(void)test_acl_setup(TEST_INPUT_READER, NULL);
	test_acl_mailbox_create(TEST_CHILD_MAILBOX);

	parent_name = mailbox_list_get_storage_name(test_acl.list,
						    TEST_MAILBOX);
	child_name = mailbox_list_get_storage_name(test_acl.list,
						   TEST_CHILD_MAILBOX);
	parent_path = test_acl_local_path(parent_name);
	test_assert(parent_path != NULL);
	if (parent_path != NULL)
		test_acl_write_file(parent_path, "user="TEST_ACL_USER" lr\n");

	aclobj = acl_object_init_from_parent(test_acl.backend, child_name);
	test_assert_strcmp(aclobj->name, parent_name);
	test_assert_strcmp(test_acl_my_rights(aclobj), "lookup read");
	acl_object_deinit(&aclobj);

	test_acl_user_deinit();
	test_end();
}

static const char *test_acl_cache_path(void)
{
	const char *root_dir;
	enum mailbox_list_path_type type;

	if (!acl_backend_get_root_dir(test_acl.backend, &root_dir, &type))
		i_fatal("acl_backend_get_root_dir() failed");
	return t_strconcat(root_dir, "/"ACL_RIGHTS_CACHE, NULL);
}

/* Create the rights cache with a full rebuild and make sure the mailbox is
   in it. */
static void test_acl_rights_cache_seed(void)
{
	const char *cache;

	test_assert(acl_backend_nonowner_lookups_rebuild(test_acl.backend,
							  FALSE) == 0);
	cache = test_acl_read_file(test_acl_cache_path());
	test_assert(cache != NULL &&
		    strstr(cache, "\t"TEST_MAILBOX"\t") != NULL);
}

/* The storage has the mailboxes' files locally at all times, so a missing
   ACL file is authoritative: the cached rights must not be served and the
   entry is evicted. */
static void test_acl_vfile_read_deleted_file_evicts(void)
{
	struct acl_object *aclobj;
	const char *path, *cache;

	test_begin("acl vfile read deleted ACL file evicts");
	path = test_acl_setup(TEST_INPUT("acl_cache_ttl=0",
					 "acl_user="TEST_ACL_USER),
			      "user="TEST_ACL_USER" lr\n");
	test_acl_rights_cache_seed();

	i_unlink(path);
	aclobj = acl_object_init_from_name(test_acl.backend, TEST_MAILBOX);
	test_assert_strcmp(test_acl_my_rights(aclobj), "");
	acl_object_deinit(&aclobj);

	cache = test_acl_read_file(test_acl_cache_path());
	test_assert(cache != NULL &&
		    strstr(cache, "\t"TEST_MAILBOX"\t") == NULL &&
		    strstr(cache, "\t"TEST_MAILBOX"\n") == NULL);

	test_acl_user_deinit();
	test_end();
}

/* An unreadable ACL file denies everything. The cached rights must not
   override that. */
static void test_acl_vfile_read_eacces_not_cached(void)
{
	struct acl_object *aclobj;
	const char *path;

	test_begin("acl vfile read EACCES not overridden by cache");
	if (geteuid() == 0) {
		/* chmod() doesn't stop root */
		test_end();
		return;
	}
	path = test_acl_setup(TEST_INPUT("acl_cache_ttl=0",
					 "acl_user="TEST_ACL_USER),
			      "user="TEST_ACL_USER" lr\n");
	test_acl_rights_cache_seed();

	if (chmod(path, 0) < 0)
		i_fatal("chmod(%s) failed: %m", path);
	aclobj = acl_object_init_from_name(test_acl.backend, TEST_MAILBOX);
	test_assert_strcmp(test_acl_my_rights(aclobj), "");
	acl_object_deinit(&aclobj);
	if (chmod(path, 0644) < 0)
		i_fatal("chmod(%s) failed: %m", path);

	test_acl_user_deinit();
	test_end();
}

/* Reading a mailbox that has no ACL file must not touch the other
   mailboxes' cache entries. */
static void test_acl_vfile_read_no_acl_keeps_cache(void)
{
	struct acl_object *aclobj;
	const char *cache_before;

	test_begin("acl vfile read without ACL file keeps cache");
	(void)test_acl_setup(TEST_INPUT("acl_cache_ttl=0",
					"acl_user="TEST_ACL_USER),
			     "user="TEST_ACL_USER" lr\n");
	test_acl_mailbox_create(TEST_CHILD_MAILBOX);
	test_acl_rights_cache_seed();
	cache_before = t_strdup(test_acl_read_file(test_acl_cache_path()));

	aclobj = acl_object_init_from_name(test_acl.backend,
		mailbox_list_get_storage_name(test_acl.list,
					      TEST_CHILD_MAILBOX));
	(void)test_acl_my_rights(aclobj);
	acl_object_deinit(&aclobj);

	test_assert_strcmp(test_acl_read_file(test_acl_cache_path()),
			   cache_before);

	test_acl_user_deinit();
	test_end();
}

/* The owner's first ACL read creates a missing cache with a full rebuild,
   so the cache exists before any ACL change - e.g. after an upgrade. */
static void test_acl_vfile_read_creates_cache(void)
{
	struct acl_object *aclobj;
	const char *cache;

	test_begin("acl vfile read creates a missing cache");
	(void)test_acl_setup(TEST_INPUT("acl_cache_ttl=0"),
			     "user="TEST_ACL_USER" lr\n");
	test_acl_mailbox_create(TEST_CHILD_MAILBOX);
	/* the mailbox creation's ACL checks may already have created it */
	i_unlink_if_exists(test_acl_cache_path());

	/* an ACL read of a mailbox without an ACL file */
	aclobj = acl_object_init_from_name(test_acl.backend,
		mailbox_list_get_storage_name(test_acl.list,
					      TEST_CHILD_MAILBOX));
	(void)test_acl_my_rights(aclobj);
	acl_object_deinit(&aclobj);

	cache = test_acl_read_file(test_acl_cache_path());
	test_assert(cache != NULL &&
		    strstr(cache, "\t"TEST_MAILBOX"\t") != NULL);

	test_acl_user_deinit();
	test_end();
}

/* A rebuild that fails doesn't leave a cache behind. It lists every
   mailbox, so it must not be retried by each ACL read, only once per
   acl_cache_ttl. */
static void test_acl_vfile_read_failed_rebuild_throttled(void)
{
	struct acl_object *aclobj;
	const char *child;

	test_begin("acl vfile read doesn't retry a failed rebuild");
	(void)test_acl_setup(TEST_INPUT("acl_cache_ttl=30s"),
			     "user="TEST_ACL_USER" lr\n");
	test_acl_mailbox_create(TEST_CHILD_MAILBOX);
	child = mailbox_list_get_storage_name(test_acl.list,
					      TEST_CHILD_MAILBOX);
	i_unlink_if_exists(test_acl_cache_path());
	/* a broken ACL file aborts the rebuild */
	test_acl_write_file(test_acl_local_path(TEST_MAILBOX),
			    "b0rken junk here\n");

	test_expect_error_string("ACL file");
	aclobj = acl_object_init_from_name(test_acl.backend, child);
	(void)test_acl_my_rights(aclobj);
	acl_object_deinit(&aclobj);
	test_expect_no_more_errors();
	test_assert(test_acl_read_file(test_acl_cache_path()) == NULL);

	/* the next read doesn't try again */
	aclobj = acl_object_init_from_name(test_acl.backend, child);
	(void)test_acl_my_rights(aclobj);
	acl_object_deinit(&aclobj);

	/* but one after acl_cache_ttl does */
	ioloop_time += 31;
	test_expect_error_string("ACL file");
	aclobj = acl_object_init_from_name(test_acl.backend, child);
	(void)test_acl_my_rights(aclobj);
	acl_object_deinit(&aclobj);
	test_expect_no_more_errors();

	test_acl_user_deinit();
	test_end();
}

static const char *test_acl_legacy_list_path(void)
{
	const char *root_dir;
	enum mailbox_list_path_type type;

	if (!acl_backend_get_root_dir(test_acl.backend, &root_dir, &type))
		i_fatal("acl_backend_get_root_dir() failed");
	return t_strconcat(root_dir, "/dovecot-acl-list", NULL);
}

static void test_acl_read_rights_of(const char *name)
{
	struct acl_object *aclobj;

	aclobj = acl_object_init_from_name(test_acl.backend, name);
	(void)test_acl_my_rights(aclobj);
	acl_object_deinit(&aclobj);
}

/* The rebuild that creates the cache removes the dovecot-acl-list an
   earlier version left behind. */
static void test_acl_vfile_read_removes_legacy_list(void)
{
	const char *cache;

	test_begin("acl vfile read removes dovecot-acl-list");
	(void)test_acl_setup(TEST_INPUT("acl_cache_ttl=0"),
			     "user="TEST_ACL_USER" lr\n");
	/* the mailbox creation's ACL checks may already have created it */
	i_unlink_if_exists(test_acl_cache_path());
	test_acl_write_file(test_acl_legacy_list_path(),
			    "0 "TEST_MAILBOX"\n");

	test_acl_read_rights_of(TEST_MAILBOX);

	cache = test_acl_read_file(test_acl_cache_path());
	test_assert(cache != NULL &&
		    strstr(cache, "\t"TEST_MAILBOX"\t") != NULL);
	test_assert(test_acl_read_file(test_acl_legacy_list_path()) == NULL);

	test_acl_user_deinit();
	test_end();
}

/* dovecot-acl-list showing up next to the cache means an earlier version
   was used again. The ACLs it changed never reached the cache, so the
   cache is rebuilt and the list removed again. */
static void test_acl_vfile_read_legacy_list_reappears(void)
{
	const char *child, *cache;

	test_begin("acl vfile read rebuilds for a new dovecot-acl-list");
	(void)test_acl_setup(TEST_INPUT("acl_cache_ttl=0"),
			     "user="TEST_ACL_USER" lr\n");
	test_acl_mailbox_create(TEST_CHILD_MAILBOX);
	child = mailbox_list_get_storage_name(test_acl.list,
					      TEST_CHILD_MAILBOX);
	test_acl_rights_cache_seed();
	test_assert(test_acl_read_file(test_acl_legacy_list_path()) == NULL);

	/* the earlier version shares another mailbox: it writes the ACL
	   file and its list, but not the cache */
	test_acl_write_file(test_acl_local_path(child),
			    "user="TEST_OTHER_USER" lr\n");
	test_acl_write_file(test_acl_legacy_list_path(),
			    t_strdup_printf("0 "TEST_MAILBOX"\n0 %s\n", child));

	/* an ACL read of the mailbox that didn't change */
	test_acl_read_rights_of(TEST_MAILBOX);

	cache = test_acl_read_file(test_acl_cache_path());
	test_assert(cache != NULL &&
		    strstr(cache, t_strdup_printf("\t%s\tuser="
				TEST_OTHER_USER"\t", child)) != NULL);
	test_assert(test_acl_read_file(test_acl_legacy_list_path()) == NULL);

	test_acl_user_deinit();
	test_end();
}

/* Only a full rebuild removes dovecot-acl-list. An earlier version sharing
   the storage would otherwise recreate it after every cache update. The
   rebuild for a list that showed up runs once acl_cache_ttl has passed. */
static void test_acl_vfile_read_legacy_list_kept_by_update(void)
{
	const char *path, *cache;
	struct stat st;
	struct utimbuf ut;

	test_begin("acl vfile cache update keeps dovecot-acl-list");
	path = test_acl_setup(TEST_INPUT("acl_cache_ttl=30s"),
			      "user="TEST_ACL_USER" lr\n");
	test_acl_rights_cache_seed();
	test_acl_write_file(test_acl_legacy_list_path(),
			    "0 "TEST_MAILBOX"\n");

	/* the ACL file changes without the cache being updated */
	test_acl_write_file(path, "user="TEST_ACL_USER" lr\n"
				  "user="TEST_OTHER_USER" lr\n");
	if (stat(path, &st) < 0)
		i_fatal("stat(%s) failed: %m", path);
	ut.actime = ut.modtime = st.st_mtime + 10;
	if (utime(path, &ut) < 0)
		i_fatal("utime(%s) failed: %m", path);

	/* reading it brings the mailbox's cache entry up to date */
	test_acl_read_rights_of(TEST_MAILBOX);
	cache = test_acl_read_file(test_acl_cache_path());
	test_assert(cache != NULL &&
		    strstr(cache, "\t"TEST_MAILBOX"\tuser="
				  TEST_OTHER_USER"\t") != NULL);
	test_assert(test_acl_read_file(test_acl_legacy_list_path()) != NULL);

	ioloop_time += 31;
	test_acl_read_rights_of(TEST_MAILBOX);
	test_assert(test_acl_read_file(test_acl_legacy_list_path()) == NULL);

	test_acl_user_deinit();
	test_end();
}

/* With a storage that has a mailbox's files locally only while the mailbox
   is open, a missing ACL file doesn't mean there is none: the cached rights
   are served and the entry stays. Reading the ACL with the mailbox open
   tells that the file is really gone: the entry stays, but without rights. */
static void test_acl_vfile_read_cached_files_missing_file(void)
{
	struct acl_object *aclobj;
	const char *path, *cache;

	test_begin("acl vfile read missing ACL file with cached files");
	path = test_acl_setup(TEST_INPUT("acl_cache_ttl=0",
					 "acl_user="TEST_ACL_USER),
			      "user="TEST_ACL_USER" lr\n");
	test_acl_storage_set_cached_files();
	test_acl_rights_cache_seed();

	i_unlink(path);
	aclobj = acl_object_init_from_name(test_acl.backend, TEST_MAILBOX);
	test_assert_strcmp(test_acl_my_rights(aclobj), "lookup read");
	cache = test_acl_read_file(test_acl_cache_path());
	test_assert(cache != NULL &&
		    strstr(cache, "\t"TEST_MAILBOX"\t") != NULL);

	test_assert(acl_mailbox_list_read_acl_opened(test_acl.list,
						     aclobj) == 0);
	test_assert_strcmp(test_acl_my_rights(aclobj), "");
	acl_object_deinit(&aclobj);
	cache = test_acl_read_file(test_acl_cache_path());
	test_assert(cache != NULL &&
		    strstr(cache, "\t-\t"TEST_MAILBOX"\n") != NULL);

	test_acl_user_deinit();
	test_end();
}

static void test_acl_set_mtime(const char *path, time_t mtime)
{
	struct utimbuf ut = { .actime = mtime, .modtime = mtime };

	if (utime(path, &ut) < 0)
		i_fatal("utime(%s) failed: %m", path);
}

/* With a storage that has a mailbox's files locally only while the mailbox
   is open, a local ACL file that is older than the cache entry is an old
   copy of a mailbox that was changed elsewhere: the cached rights are
   served. A newer file is used, and the entry follows it. */
static void test_acl_vfile_read_cached_files_old_file(void)
{
	struct acl_object *aclobj;
	const char *path;
	struct stat st;

	test_begin("acl vfile read old ACL file with cached files");
	path = test_acl_setup(TEST_INPUT("acl_cache_ttl=0",
					 "acl_user="TEST_ACL_USER),
			      "user="TEST_ACL_USER" lr\n");
	test_acl_storage_set_cached_files();
	test_acl_rights_cache_seed();
	if (stat(path, &st) < 0)
		i_fatal("stat(%s) failed: %m", path);

	/* other rights in a file that is older than the entry */
	test_acl_write_file(path, "user="TEST_ACL_USER" lrw\n");
	test_acl_set_mtime(path, st.st_mtime - 10);
	aclobj = acl_object_init_from_name(test_acl.backend, TEST_MAILBOX);
	test_assert_strcmp(test_acl_my_rights(aclobj), "lookup read");
	acl_object_deinit(&aclobj);

	/* the same file, now newer than the entry */
	test_acl_set_mtime(path, st.st_mtime + 10);
	aclobj = acl_object_init_from_name(test_acl.backend, TEST_MAILBOX);
	test_assert_strcmp(test_acl_my_rights(aclobj), "lookup read write");
	acl_object_deinit(&aclobj);

	/* the entry has the file's rights now: they are served when the
	   file isn't there */
	i_unlink(path);
	aclobj = acl_object_init_from_name(test_acl.backend, TEST_MAILBOX);
	test_assert_strcmp(test_acl_my_rights(aclobj), "lookup read write");
	acl_object_deinit(&aclobj);

	test_acl_user_deinit();
	test_end();
}

/* With a storage that has a mailbox's files locally only while the mailbox
   is open, a mailbox whose rights were all removed keeps its line in the
   cache. An old local copy of the ACL file is older than that line and
   doesn't bring the rights back. */
static void test_acl_vfile_read_cached_files_removed_rights(void)
{
	struct acl_rights_update update = {
		.modify_mode = ACL_MODIFY_MODE_CLEAR,
		.neg_modify_mode = ACL_MODIFY_MODE_CLEAR,
	};
	struct acl_object *aclobj;
	const char *path, *cache, *error;
	struct stat st;

	test_begin("acl vfile read removed rights with cached files");
	path = test_acl_setup(TEST_INPUT("acl_cache_ttl=0",
					 "acl_user="TEST_ACL_USER),
			      "user="TEST_ACL_USER" lr\n");
	test_acl_storage_set_cached_files();
	test_acl_rights_cache_seed();

	if (acl_rights_update_import(&update, "user="TEST_ACL_USER, NULL,
				     &error) < 0)
		i_fatal("acl_rights_update_import() failed: %s", error);
	aclobj = acl_object_init_from_name(test_acl.backend, TEST_MAILBOX);
	test_assert(acl_object_update(aclobj, &update) == 0);
	acl_object_deinit(&aclobj);
	cache = test_acl_read_file(test_acl_cache_path());
	test_assert(cache != NULL &&
		    strstr(cache, "\t-\t"TEST_MAILBOX"\n") != NULL);

	/* an old copy of the ACL file that still has the rights */
	if (stat(path, &st) < 0)
		i_fatal("stat(%s) failed: %m", path);
	test_acl_write_file(path, "user="TEST_ACL_USER" lr\n");
	test_acl_set_mtime(path, st.st_mtime - 10);
	aclobj = acl_object_init_from_name(test_acl.backend, TEST_MAILBOX);
	test_assert_strcmp(test_acl_my_rights(aclobj), "");
	acl_object_deinit(&aclobj);
	cache = test_acl_read_file(test_acl_cache_path());
	test_assert(cache != NULL &&
		    strstr(cache, "\t-\t"TEST_MAILBOX"\n") != NULL);

	test_acl_user_deinit();
	test_end();
}

/* With a storage that has a mailbox's files locally only while the mailbox
   is open, the line of a mailbox that is no longer in the mailbox list is
   dropped, not kept without rights. */
static void test_acl_vfile_read_cached_files_gone_mailbox(void)
{
	struct acl_object *aclobj;
	struct mailbox *box;
	const char *cache;

	test_begin("acl vfile read gone mailbox with cached files");
	(void)test_acl_setup(TEST_INPUT("acl_cache_ttl=0",
					"acl_user="TEST_ACL_USER),
			     "user="TEST_ACL_USER" lr\n");
	test_acl_storage_set_cached_files();
	test_acl_rights_cache_seed();

	/* deleted without the ACL plugin seeing it */
	box = mailbox_alloc(test_acl.list, TEST_MAILBOX, 0);
	if (mailbox_delete(box) < 0) {
		i_fatal("mailbox_delete(%s) failed: %s", TEST_MAILBOX,
			mailbox_get_last_internal_error(box, NULL));
	}
	mailbox_free(&box);

	aclobj = acl_object_init_from_name(test_acl.backend, TEST_MAILBOX);
	test_assert_strcmp(test_acl_my_rights(aclobj), "");
	acl_object_deinit(&aclobj);
	cache = test_acl_read_file(test_acl_cache_path());
	test_assert(cache != NULL &&
		    strstr(cache, "\t"TEST_MAILBOX"\t") == NULL &&
		    strstr(cache, "\t"TEST_MAILBOX"\n") == NULL);

	test_acl_user_deinit();
	test_end();
}

/* A dovecot-acl-list that can't be parsed is ignored and removed by the
   rebuild instead of blocking it. */
static void test_acl_vfile_read_broken_legacy_list(void)
{
	const char *cache;

	test_begin("acl vfile read ignores a broken dovecot-acl-list");
	(void)test_acl_setup(TEST_INPUT("acl_cache_ttl=0"),
			     "user="TEST_ACL_USER" lr\n");
	/* the mailbox creation's ACL checks may already have created it */
	i_unlink_if_exists(test_acl_cache_path());
	test_acl_write_file(test_acl_legacy_list_path(),
			    "0 "TEST_MAILBOX"\nbroken\n");

	test_expect_error_string("Broken dovecot-acl-list file");
	test_acl_read_rights_of(TEST_MAILBOX);
	test_expect_no_more_errors();

	cache = test_acl_read_file(test_acl_cache_path());
	test_assert(cache != NULL &&
		    strstr(cache, "\t"TEST_MAILBOX"\t") != NULL);
	test_assert(test_acl_read_file(test_acl_legacy_list_path()) == NULL);

	test_acl_user_deinit();
	test_end();
}

int main(int argc, char **argv)
{
	static void (*const test_functions[])(void) = {
		test_acl_vfile_owner_defaults,
		test_acl_vfile_nonowner_defaults,
		test_acl_vfile_local_file,
		test_acl_vfile_comments,
		test_acl_vfile_negative_rights,
		test_acl_vfile_id_precedence,
		test_acl_vfile_owner_entry,
		test_acl_vfile_fresh_object_cache,
		test_acl_vfile_cache_ttl,
		test_acl_vfile_file_changed,
		test_acl_vfile_read_deleted_file_evicts,
		test_acl_vfile_read_eacces_not_cached,
		test_acl_vfile_read_no_acl_keeps_cache,
		test_acl_vfile_read_creates_cache,
		test_acl_vfile_read_failed_rebuild_throttled,
		test_acl_vfile_read_removes_legacy_list,
		test_acl_vfile_read_legacy_list_reappears,
		test_acl_vfile_read_legacy_list_kept_by_update,
		test_acl_vfile_read_broken_legacy_list,
		test_acl_vfile_read_cached_files_missing_file,
		test_acl_vfile_read_cached_files_old_file,
		test_acl_vfile_read_cached_files_removed_rights,
		test_acl_vfile_read_cached_files_gone_mailbox,
		test_acl_vfile_last_changed,
		test_acl_vfile_parse_error,
		test_acl_vfile_defaults_from_inbox,
		test_acl_vfile_config_rights,
		test_acl_vfile_parent,
		NULL
	};
	int ret;

	test_acl_common_init("test-acl-vfile", &argc, &argv);
	ret = test_run(test_functions);
	test_acl_common_deinit();
	return ret;
}
