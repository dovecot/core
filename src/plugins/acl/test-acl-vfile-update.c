/* Copyright (c) Dovecot authors, see top-level COPYING file */

/* Tests for the vfile ACL backend's write path: acl_object_update() and the
   acl-rights.cache file it maintains. */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "test-common.h"
#include "mail-storage.h"
#include "mailbox-list.h"
#include "acl-cache.h"
#include "acl-storage.h"
#include "acl-backend-vfile.h"
#include "acl-rights-cache.h"
#include "test-acl-common.h"

#include <sys/stat.h>

#define TEST_MAILBOX "Test"
#define TEST_MAILBOX2 "Test2"
#define TEST_MAILBOX3 "Test3"
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

static const char *test_acl_cache_path(void)
{
	const char *root_dir;
	enum mailbox_list_path_type type;

	if (!acl_backend_get_root_dir(test_acl.backend, &root_dir, &type))
		i_fatal("acl_backend_get_root_dir() failed");
	return t_strconcat(root_dir, "/"ACL_RIGHTS_CACHE, NULL);
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

static void test_acl_vfile_update_config_rights(void)
{
	struct acl_object *aclobj;

	test_begin("acl vfile update configured rights");
	/* The configuration has "acl anyone { rights = lr }" and the mailbox
	   has no dovecot-acl file. */
	test_acl_update_setup(TEST_INPUT("acl+=anyone",
					 "acl/anyone/acl_rights=lr"));
	test_assert(test_acl_read_file(test_acl_path) == NULL);

	aclobj = acl_object_init_from_name(test_acl.backend, TEST_MAILBOX);
	/* the configured entry is listed as global */
	test_assert_strcmp(test_acl_list(aclobj),
			   "anyone lookup read (global)");
	/* Add rights for a user. This writes the dovecot-acl file, which
	   must contain only the added entry. The configured (global) entry
	   must not be written into it. */
	test_assert(test_acl_do_update(aclobj, TEST_UPDATE_ID,
				       TEST_RIGHTS(MAIL_ACL_LOOKUP,
						   MAIL_ACL_READ),
				       ACL_MODIFY_MODE_ADD,
				       ACL_MODIFY_MODE_ADD) == 0);
	test_assert_strcmp(test_acl_read_file(test_acl_path),
			   TEST_UPDATE_ID" lr\n");
	/* the object still has both entries, the global one last */
	test_assert_strcmp(test_acl_list(aclobj),
			   TEST_UPDATE_ID" lookup read, "
			   "anyone lookup read (global)");

	acl_object_deinit(&aclobj);
	test_acl_user_deinit();
	test_end();
}

static void test_acl_vfile_rights_cache(void)
{
	struct acl_mailbox_list_context *ctx;
	struct acl_object *aclobj;
	const char *cache_path, *name;
	unsigned int count = 0;

	test_begin("acl vfile rights cache");
	test_acl_update_setup(NULL);
	test_acl_mailbox_create(TEST_MAILBOX2);
	test_acl_mailbox_create(TEST_MAILBOX3);

	/* Test2 has ACLs, but none of them give a non-owner the lookup
	   right. Test3 only has an owner entry, whose lookup right doesn't
	   count either. Both get cached, but neither belongs in the
	   non-owner lookup iteration. */
	test_acl_write_file(test_acl_local_path(TEST_MAILBOX2),
			    TEST_UPDATE_ID" r\n");
	test_acl_write_file(test_acl_local_path(TEST_MAILBOX3), "owner l\n");

	cache_path = test_acl_cache_path();

	/* the first update creates the rights cache with a full rebuild,
	   which picks up all mailboxes' ACL files */
	aclobj = acl_object_init_from_name(test_acl.backend, TEST_MAILBOX);
	test_assert(test_acl_do_update(aclobj, TEST_UPDATE_ID,
				       TEST_RIGHTS(MAIL_ACL_LOOKUP,
						   MAIL_ACL_READ),
				       ACL_MODIFY_MODE_ADD,
				       ACL_MODIFY_MODE_ADD) == 0);
	acl_object_deinit(&aclobj);

	const char *cache = test_acl_read_file(cache_path);
	test_assert(cache != NULL);
	test_assert(cache != NULL &&
		    strstr(cache, "\t"TEST_MAILBOX"\t") != NULL);
	test_assert(cache != NULL &&
		    strstr(cache, "\t"TEST_MAILBOX2"\t") != NULL);
	test_assert(cache != NULL &&
		    strstr(cache, "\t"TEST_MAILBOX3"\t") != NULL);

	/* only the mailbox with non-owner lookup rights shows up in the
	   non-owner lookup iteration */
	ctx = acl_backend_nonowner_lookups_iter_init(test_acl.backend);
	while (acl_backend_nonowner_lookups_iter_next(ctx, &name)) {
		count++;
		test_assert_strcmp(name, TEST_MAILBOX);
	}
	test_assert(acl_backend_nonowner_lookups_iter_deinit(&ctx) == 1);
	test_assert_cmp(count, ==, 1);

	/* an explicit rebuild produces the same result */
	test_assert(acl_backend_nonowner_lookups_rebuild(
			test_acl.backend) == 0);
	count = 0;
	ctx = acl_backend_nonowner_lookups_iter_init(test_acl.backend);
	while (acl_backend_nonowner_lookups_iter_next(ctx, &name)) {
		count++;
		test_assert_strcmp(name, TEST_MAILBOX);
	}
	test_assert(acl_backend_nonowner_lookups_iter_deinit(&ctx) == 1);
	test_assert_cmp(count, ==, 1);

	test_acl_user_deinit();
	test_end();
}

static void test_acl_vfile_rights_cache_corrupt(void)
{
	struct acl_mailbox_list_context *ctx;
	struct acl_object *aclobj;
	const char *cache_path, *name;
	unsigned int count = 0;

	test_begin("acl vfile rights cache corrupt");
	test_acl_update_setup(TEST_INPUT("acl_cache_ttl=0"));

	cache_path = test_acl_cache_path();

	/* the first update creates the rights cache */
	aclobj = acl_object_init_from_name(test_acl.backend, TEST_MAILBOX);
	test_assert(test_acl_do_update(aclobj, TEST_UPDATE_ID,
				       TEST_RIGHTS(MAIL_ACL_LOOKUP,
						   MAIL_ACL_READ),
				       ACL_MODIFY_MODE_ADD,
				       ACL_MODIFY_MODE_ADD) == 0);
	acl_object_deinit(&aclobj);
	test_assert(test_acl_read_file(cache_path) != NULL);

	test_acl_write_file(cache_path, "V1\nbroken\n");

	/* A corrupt cache must not be treated as an authoritative empty
	   result - that would make the ACL lookup dict rebuild remove the
	   user's existing share entries. The iteration's refresh notices
	   the read failure and recovers with a rebuild: one read error
	   from the refresh, a second from the rebuild's re-read under the
	   lock. */
	test_expect_error_string_n_times("Invalid number of fields", 2);
	ctx = acl_backend_nonowner_lookups_iter_init(test_acl.backend);
	while (acl_backend_nonowner_lookups_iter_next(ctx, &name)) {
		count++;
		test_assert_strcmp(name, TEST_MAILBOX);
	}
	test_assert(acl_backend_nonowner_lookups_iter_deinit(&ctx) == 1);
	test_expect_no_more_errors();
	test_assert_cmp(count, ==, 1);

	/* the rebuild replaced the corrupt file */
	const char *cache = test_acl_read_file(cache_path);
	test_assert(cache != NULL && strstr(cache, "broken") == NULL);
	test_assert(cache != NULL &&
		    strstr(cache, "\t"TEST_MAILBOX"\t") != NULL);

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
		test_acl_vfile_update_config_rights,
		test_acl_vfile_rights_cache,
		test_acl_vfile_rights_cache_corrupt,
		NULL
	};
	int ret;

	test_acl_common_init("test-acl-vfile-update", &argc, &argv);
	ret = test_run(test_functions);
	test_acl_common_deinit();
	return ret;
}
