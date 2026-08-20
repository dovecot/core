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
#include "acl-backend-vfile.h"
#include "test-acl-common.h"

#include <unistd.h>

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
	   silently granting the rights of the lines before it */
	test_expect_error_string("line 2: Unknown ID 'bogus'");
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
		test_acl_vfile_last_changed,
		test_acl_vfile_parse_error,
		test_acl_vfile_defaults_from_inbox,
		test_acl_vfile_parent,
		NULL
	};
	int ret;

	test_acl_common_init("test-acl-vfile", &argc, &argv);
	ret = test_run(test_functions);
	test_acl_common_deinit();
	return ret;
}
