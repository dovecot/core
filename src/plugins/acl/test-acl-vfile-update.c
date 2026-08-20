/* Copyright (c) Dovecot authors, see top-level COPYING file */

/* Tests for the vfile ACL backend's write path: acl_object_update() and the
   dovecot-acl-list file it maintains. */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "test-common.h"
#include "mail-storage.h"
#include "mailbox-list.h"
#include "acl-cache.h"
#include "acl-backend-vfile.h"
#include "test-acl-common.h"

#include <sys/stat.h>

#define TEST_MAILBOX "Test"
#define TEST_MAILBOX2 "Test2"
#define TEST_UPDATE_ID "user="TEST_ACL_USER

/* NULL-terminated userdb field list */
#define TEST_INPUT(...) ((const char *const []){ __VA_ARGS__, NULL })
/* NULL-terminated right name list for acl_rights_update_import() */
#define TEST_RIGHTS(...) ((const char *const []){ __VA_ARGS__, NULL })

static const char *test_acl_path;

static void test_acl_update_setup(const char *const *extra_input)
{
	test_acl_user_init(extra_input);
	test_acl_mailbox_create(TEST_MAILBOX);
	test_acl_path = test_acl_local_path(TEST_MAILBOX);
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

static void test_acl_vfile_update_insert(void)
{
	struct acl_object *aclobj;

	test_begin("acl vfile update insert");
	test_acl_update_setup(NULL);
	test_assert(test_acl_read_file(test_acl_path) == NULL);

	aclobj = acl_object_init_from_name(test_acl.backend, TEST_MAILBOX);
	test_assert(test_acl_do_update(aclobj, TEST_UPDATE_ID,
				       TEST_RIGHTS(MAIL_ACL_LOOKUP,
						   MAIL_ACL_READ),
				       ACL_MODIFY_MODE_ADD,
				       ACL_MODIFY_MODE_ADD) == 0);
	test_assert_strcmp(test_acl_read_file(test_acl_path),
			   TEST_UPDATE_ID" lr\n");
	test_assert_strcmp(test_acl_list(aclobj),
			   TEST_UPDATE_ID" lookup read");

	/* a second identifier is added, keeping the file sorted */
	test_assert(test_acl_do_update(aclobj, "anyone",
				       TEST_RIGHTS(MAIL_ACL_LOOKUP),
				       ACL_MODIFY_MODE_ADD,
				       ACL_MODIFY_MODE_ADD) == 0);
	test_assert_strcmp(test_acl_read_file(test_acl_path),
			   "anyone l\n"TEST_UPDATE_ID" lr\n");

	acl_object_deinit(&aclobj);
	test_acl_user_deinit();
	test_end();
}

static void test_acl_vfile_update_modify(void)
{
	struct acl_object *aclobj;

	test_begin("acl vfile update modify");
	test_acl_update_setup(NULL);
	test_acl_write_file(test_acl_path, TEST_UPDATE_ID" lr\n");

	aclobj = acl_object_init_from_name(test_acl.backend, TEST_MAILBOX);
	/* adding to an existing identifier merges the rights */
	test_assert(test_acl_do_update(aclobj, TEST_UPDATE_ID,
				       TEST_RIGHTS(MAIL_ACL_INSERT),
				       ACL_MODIFY_MODE_ADD,
				       ACL_MODIFY_MODE_ADD) == 0);
	test_assert_strcmp(test_acl_read_file(test_acl_path),
			   TEST_UPDATE_ID" ilr\n");

	/* removing takes them away again */
	test_assert(test_acl_do_update(aclobj, TEST_UPDATE_ID,
				       TEST_RIGHTS(MAIL_ACL_INSERT),
				       ACL_MODIFY_MODE_REMOVE,
				       ACL_MODIFY_MODE_REMOVE) == 0);
	test_assert_strcmp(test_acl_read_file(test_acl_path),
			   TEST_UPDATE_ID" lr\n");

	/* replacing drops whatever was there before */
	test_assert(test_acl_do_update(aclobj, TEST_UPDATE_ID,
				       TEST_RIGHTS(MAIL_ACL_ADMIN),
				       ACL_MODIFY_MODE_REPLACE,
				       ACL_MODIFY_MODE_REPLACE) == 0);
	test_assert_strcmp(test_acl_read_file(test_acl_path),
			   TEST_UPDATE_ID" a\n");

	acl_object_deinit(&aclobj);
	test_acl_user_deinit();
	test_end();
}

static void test_acl_vfile_update_delete_id(void)
{
	struct acl_object *aclobj;

	test_begin("acl vfile update delete identifier");
	test_acl_update_setup(NULL);
	test_acl_write_file(test_acl_path,
			    "anyone l\n"TEST_UPDATE_ID" lr\n");

	aclobj = acl_object_init_from_name(test_acl.backend, TEST_MAILBOX);
	/* an identifier left with no rights at all is dropped */
	test_assert(test_acl_do_update(aclobj, TEST_UPDATE_ID,
				       TEST_RIGHTS(MAIL_ACL_LOOKUP,
						   MAIL_ACL_READ),
				       ACL_MODIFY_MODE_REMOVE,
				       ACL_MODIFY_MODE_REMOVE) == 0);
	test_assert_strcmp(test_acl_read_file(test_acl_path), "anyone l\n");

	/* clearing does the same */
	test_assert(test_acl_do_update(aclobj, "anyone", NULL,
				       ACL_MODIFY_MODE_CLEAR,
				       ACL_MODIFY_MODE_CLEAR) == 0);
	test_assert_strcmp(test_acl_read_file(test_acl_path), "");
	test_assert_strcmp(test_acl_list(aclobj), "");

	acl_object_deinit(&aclobj);
	test_acl_user_deinit();
	test_end();
}

static void test_acl_vfile_update_noop(void)
{
	struct acl_object *aclobj;

	test_begin("acl vfile update no-op");
	test_acl_update_setup(NULL);
	test_acl_write_file(test_acl_path, TEST_UPDATE_ID" lr\n");

	aclobj = acl_object_init_from_name(test_acl.backend, TEST_MAILBOX);
	/* adding rights that are already there doesn't rewrite the file */
	test_assert(test_acl_do_update(aclobj, TEST_UPDATE_ID,
				       TEST_RIGHTS(MAIL_ACL_LOOKUP),
				       ACL_MODIFY_MODE_ADD,
				       ACL_MODIFY_MODE_ADD) == 0);
	test_assert_strcmp(test_acl_read_file(test_acl_path),
			   TEST_UPDATE_ID" lr\n");

	/* and neither does removing rights that aren't there */
	test_assert(test_acl_do_update(aclobj, TEST_UPDATE_ID,
				       TEST_RIGHTS(MAIL_ACL_ADMIN),
				       ACL_MODIFY_MODE_REMOVE,
				       ACL_MODIFY_MODE_REMOVE) == 0);
	test_assert_strcmp(test_acl_read_file(test_acl_path),
			   TEST_UPDATE_ID" lr\n");

	/* removing an identifier that doesn't exist at all is fine too */
	test_assert(test_acl_do_update(aclobj, "group=nobody",
				       TEST_RIGHTS(MAIL_ACL_LOOKUP),
				       ACL_MODIFY_MODE_REMOVE,
				       ACL_MODIFY_MODE_REMOVE) == 0);
	test_assert_strcmp(test_acl_read_file(test_acl_path),
			   TEST_UPDATE_ID" lr\n");

	acl_object_deinit(&aclobj);
	test_acl_user_deinit();
	test_end();
}

static void test_acl_vfile_update_negative(void)
{
	struct acl_object *aclobj;

	test_begin("acl vfile update negative rights");
	test_acl_update_setup(NULL);

	aclobj = acl_object_init_from_name(test_acl.backend, TEST_MAILBOX);
	/* a '-' prefix in the imported rights makes them negative */
	test_assert(test_acl_do_update(aclobj, TEST_UPDATE_ID,
				       TEST_RIGHTS("-"MAIL_ACL_LOOKUP),
				       ACL_MODIFY_MODE_REPLACE,
				       ACL_MODIFY_MODE_REPLACE) == 0);
	test_assert_strcmp(test_acl_read_file(test_acl_path),
			   "-"TEST_UPDATE_ID" l\n");

	/* positive and negative rights for the same identifier are written
	   as two lines */
	test_assert(test_acl_do_update(aclobj, TEST_UPDATE_ID,
				       TEST_RIGHTS(MAIL_ACL_READ),
				       ACL_MODIFY_MODE_ADD,
				       ACL_MODIFY_MODE_ADD) == 0);
	test_assert_strcmp(test_acl_read_file(test_acl_path),
			   TEST_UPDATE_ID" r\n"
			   "-"TEST_UPDATE_ID" l\n");
	test_assert_strcmp(test_acl_list(aclobj),
			   TEST_UPDATE_ID" read -lookup");

	acl_object_deinit(&aclobj);
	test_acl_user_deinit();
	test_end();
}

static void test_acl_vfile_update_quoted_id(void)
{
	struct acl_object *aclobj;

	test_begin("acl vfile update quoted identifier");
	test_acl_update_setup(NULL);

	aclobj = acl_object_init_from_name(test_acl.backend, TEST_MAILBOX);
	/* identifiers containing spaces are quoted when written */
	test_assert(test_acl_do_update(aclobj, "user=foo bar",
				       TEST_RIGHTS(MAIL_ACL_LOOKUP),
				       ACL_MODIFY_MODE_ADD,
				       ACL_MODIFY_MODE_ADD) == 0);
	test_assert_strcmp(test_acl_read_file(test_acl_path),
			   "\"user=foo bar\" l\n");
	/* and read back unquoted */
	test_assert_strcmp(test_acl_list(aclobj), "user=foo bar lookup");

	acl_object_deinit(&aclobj);
	test_acl_user_deinit();
	test_end();
}

static void test_acl_vfile_update_named_rights(void)
{
	struct acl_object *aclobj;

	test_begin("acl vfile update named rights");
	test_acl_update_setup(NULL);

	aclobj = acl_object_init_from_name(test_acl.backend, TEST_MAILBOX);
	/* non-standard rights have no letter, so they're written by name */
	test_assert(test_acl_do_update(aclobj, TEST_UPDATE_ID,
				       TEST_RIGHTS(MAIL_ACL_LOOKUP,
						   ":custom"),
				       ACL_MODIFY_MODE_ADD,
				       ACL_MODIFY_MODE_ADD) == 0);
	test_assert_strcmp(test_acl_read_file(test_acl_path),
			   TEST_UPDATE_ID" l :custom\n");
	test_assert_strcmp(test_acl_list(aclobj),
			   TEST_UPDATE_ID" custom lookup");

	acl_object_deinit(&aclobj);
	test_acl_user_deinit();
	test_end();
}

static void test_acl_vfile_update_last_change(void)
{
	struct acl_object *aclobj;
	struct acl_rights_update update = {
		.modify_mode = ACL_MODIFY_MODE_ADD,
		.neg_modify_mode = ACL_MODIFY_MODE_ADD,
		.last_change = 1000000000,
	};
	struct stat st;
	time_t last_changed;
	const char *error;

	test_begin("acl vfile update last_change");
	test_acl_update_setup(NULL);

	aclobj = acl_object_init_from_name(test_acl.backend, TEST_MAILBOX);
	if (acl_rights_update_import(&update, TEST_UPDATE_ID,
				     TEST_RIGHTS(MAIL_ACL_LOOKUP), &error) < 0)
		i_fatal("acl_rights_update_import() failed: %s", error);
	test_assert(acl_object_update(aclobj, &update) == 0);

	/* the file's mtime is forced to last_change when it is newer than
	   the file's original mtime */
	if (stat(test_acl_path, &st) < 0)
		i_fatal("stat(%s) failed: %m", test_acl_path);
	test_assert_cmp(st.st_mtime, ==, 1000000000);
	test_assert(acl_object_last_changed(aclobj, &last_changed) == 0);
	test_assert_cmp(last_changed, ==, 1000000000);

	acl_object_deinit(&aclobj);
	test_acl_user_deinit();
	test_end();
}

static void test_acl_vfile_update_no_local_path(void)
{
	struct acl_object *aclobj;

	test_begin("acl vfile update without a local path");
	test_acl_user_init(TEST_INPUT("acl_globals_only=yes"));
	test_acl_mailbox_create(TEST_MAILBOX);
	test_assert(test_acl_local_path(TEST_MAILBOX) == NULL);

	aclobj = acl_object_init_from_name(test_acl.backend, TEST_MAILBOX);
	test_expect_error_string("No local acl file path");
	test_assert(test_acl_do_update(aclobj, TEST_UPDATE_ID,
				       TEST_RIGHTS(MAIL_ACL_LOOKUP),
				       ACL_MODIFY_MODE_ADD,
				       ACL_MODIFY_MODE_ADD) < 0);
	test_expect_no_more_errors();

	acl_object_deinit(&aclobj);
	test_acl_user_deinit();
	test_end();
}

static void test_acl_vfile_acllist(void)
{
	struct acl_backend_vfile *backend;
	struct acl_mailbox_list_context *ctx;
	struct acl_object *aclobj;
	const char *acllist_path, *root_dir, *name;
	unsigned int count = 0;

	test_begin("acl vfile acllist");
	test_acl_update_setup(NULL);
	test_acl_mailbox_create(TEST_MAILBOX2);

	backend = container_of(test_acl.backend, struct acl_backend_vfile,
			       backend);
	if (!mailbox_list_get_root_path(test_acl.list,
					MAILBOX_LIST_PATH_TYPE_MAILBOX,
					&root_dir))
		i_fatal("mailbox_list_get_root_path() failed");
	acllist_path = t_strconcat(root_dir, "/"ACLLIST_FILENAME, NULL);

	/* granting a non-owner the lookup right rebuilds dovecot-acl-list */
	aclobj = acl_object_init_from_name(test_acl.backend, TEST_MAILBOX);
	test_assert(test_acl_do_update(aclobj, TEST_UPDATE_ID,
				       TEST_RIGHTS(MAIL_ACL_LOOKUP,
						   MAIL_ACL_READ),
				       ACL_MODIFY_MODE_ADD,
				       ACL_MODIFY_MODE_ADD) == 0);
	acl_object_deinit(&aclobj);

	const char *acllist = test_acl_read_file(acllist_path);
	test_assert(acllist != NULL);
	test_assert(acllist != NULL &&
		    strstr(acllist, " "TEST_MAILBOX"\n") != NULL);
	test_assert(acllist != NULL &&
		    strstr(acllist, " "TEST_MAILBOX2"\n") == NULL);

	/* and the mailbox shows up in the non-owner lookup iteration */
	ctx = acl_backend_nonowner_lookups_iter_init(test_acl.backend);
	while (acl_backend_nonowner_lookups_iter_next(ctx, &name)) {
		count++;
		test_assert_strcmp(name, TEST_MAILBOX);
	}
	test_assert(acl_backend_nonowner_lookups_iter_deinit(&ctx) == 1);
	test_assert(count == 1);

	/* an explicit rebuild produces the same result */
	test_assert(acl_backend_nonowner_lookups_rebuild(
			test_acl.backend) == 0);
	test_assert(array_count(&backend->acllist) == 1);

	test_acl_user_deinit();
	test_end();
}

int main(int argc, char **argv)
{
	static void (*const test_functions[])(void) = {
		test_acl_vfile_update_insert,
		test_acl_vfile_update_modify,
		test_acl_vfile_update_delete_id,
		test_acl_vfile_update_noop,
		test_acl_vfile_update_negative,
		test_acl_vfile_update_quoted_id,
		test_acl_vfile_update_named_rights,
		test_acl_vfile_update_last_change,
		test_acl_vfile_update_no_local_path,
		test_acl_vfile_acllist,
		NULL
	};
	int ret;

	test_acl_common_init("test-acl-vfile-update", &argc, &argv);
	ret = test_run(test_functions);
	test_acl_common_deinit();
	return ret;
}
