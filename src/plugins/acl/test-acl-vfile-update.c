/* Copyright (c) Dovecot authors, see top-level COPYING file */

/* Tests for the vfile ACL backend's write path: acl_object_update() and the
   acl-rights.cache file it maintains. */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "strescape.h"
#include "test-common.h"
#include "mail-storage-private.h"
#include "mailbox-list.h"
#include "acl-cache.h"
#include "acl-storage.h"
#include "acl-backend-vfile.h"
#include "acl-plugin.h"
#include "acl-rights-cache.h"
#include "test-acl-common.h"

#include <sys/stat.h>

#define TEST_MAILBOX "Test"
#define TEST_MAILBOX2 "Test2"
#define TEST_MAILBOX3 "Test3"
#define TEST_MAILBOX_CHILD TEST_MAILBOX"/child"
#define TEST_MAILBOX2_CHILD TEST_MAILBOX2"/child"
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

/* An ACL update must rebuild the process-wide rights mask itself:
   acl_backend_vfile_update_begin() rebuilds it from the pre-update file
   under the lock, and the updated validity matches the written file, so
   with a working acl_cache_ttl a stale mask would be undetectable and
   served for the whole TTL. */
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

static void test_acl_vfile_update_own_change_visible(void)
{
	struct acl_object *aclobj;

	test_begin("acl vfile update own change visible");
	test_acl_user_init(TEST_INPUT("acl_user="TEST_ACL_USER,
				      "acl_cache_ttl=30s"));
	test_acl_mailbox_create(TEST_MAILBOX);

	aclobj = acl_object_init_from_name(test_acl.backend, TEST_MAILBOX);
	/* prime the rights mask from the pre-update state */
	test_assert_strcmp(test_acl_my_rights(aclobj), "");

	test_assert(test_acl_do_update(aclobj, TEST_UPDATE_ID,
				       TEST_RIGHTS(MAIL_ACL_LOOKUP,
						   MAIL_ACL_READ),
				       ACL_MODIFY_MODE_ADD,
				       ACL_MODIFY_MODE_ADD) == 0);
	/* the process's own change is visible right away, not only after
	   acl_cache_ttl */
	test_assert_strcmp(test_acl_my_rights(aclobj), "lookup read");

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
	test_assert(acl_backend_nonowner_lookups_rebuild(test_acl.backend,
							  FALSE) == 0);
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

/* Returns the mtime field of the mailbox's acl-rights.cache line and the
   number of lines it has, which must never be more than one. The file holds
   storage names, which differ from vnames on layouts with their own
   hierarchy separator. */
static const char *
test_acl_cache_field(const char *cache_path, const char *vname,
		     unsigned int field_idx, unsigned int *count_r)
{
	const char *cache = test_acl_read_file(cache_path);
	const char *name = mailbox_list_get_storage_name(test_acl.list, vname);
	const char *value = NULL;

	*count_r = 0;
	if (cache == NULL)
		return NULL;

	for (const char *const *line = t_strsplit(cache, "\n");
	     *line != NULL; line++) {
		/* <mtime> TAB <flags> TAB <name> ... */
		const char *const *fields = t_strsplit_tabescaped(*line);

		if (str_array_length(fields) < 3 ||
		    strcmp(fields[2], name) != 0)
			continue;
		if (*count_r == 0)
			value = t_strdup(fields[field_idx]);
		*count_r += 1;
	}
	return value;
}

static const char *
test_acl_cache_lookup(const char *cache_path, const char *vname,
		      unsigned int *count_r)
{
	return test_acl_cache_field(cache_path, vname, 0, count_r);
}

static bool test_acl_cache_has(const char *cache_path, const char *vname)
{
	unsigned int count;

	(void)test_acl_cache_lookup(cache_path, vname, &count);
	return count > 0;
}

static const char *
test_acl_cache_flags(const char *cache_path, const char *vname)
{
	unsigned int count;

	return test_acl_cache_field(cache_path, vname, 1, &count);
}

/* Replace the flags of the mailbox's cache line, which must have none yet. */
static void test_acl_cache_set_flags(const char *cache_path, const char *vname,
				     const char *flags)
{
	const char *cache = test_acl_read_file(cache_path);
	const char *name = mailbox_list_get_storage_name(test_acl.list, vname);
	const char *old_fields = t_strdup_printf("\t-\t%s\t", name);
	const char *p = cache == NULL ? NULL : strstr(cache, old_fields);

	i_assert(p != NULL);
	test_acl_write_file(cache_path,
		t_strconcat(t_strdup_until(cache, p), "\t", flags, "\t", name,
			    "\t", p + strlen(old_fields), NULL));
}

/* Add a line to the cache file, in front of the existing entries. */
static void
test_acl_cache_prepend_line(const char *cache_path, const char *line)
{
	const char *cache = test_acl_read_file(cache_path);
	const char *entries = cache == NULL ? NULL : strchr(cache, '\n');

	i_assert(entries != NULL);
	test_acl_write_file(cache_path,
			    t_strconcat("V1\n", line, entries + 1, NULL));
}

static void test_acl_grant_nonowner_lookup(const char *vname)
{
	struct acl_object *aclobj = acl_object_init_from_name(test_acl.backend,
		mailbox_list_get_storage_name(test_acl.list, vname));

	test_assert(test_acl_do_update(aclobj, TEST_UPDATE_ID,
				       TEST_RIGHTS(MAIL_ACL_LOOKUP,
						   MAIL_ACL_READ),
				       ACL_MODIFY_MODE_ADD,
				       ACL_MODIFY_MODE_ADD) == 0);
	acl_object_deinit(&aclobj);
}

static void test_acl_mailbox_rename(const char *src_name, const char *dest_name)
{
	struct mailbox *src = mailbox_alloc(test_acl.list, src_name, 0);
	struct mailbox *dest = mailbox_alloc(test_acl.list, dest_name, 0);

	if (mailbox_rename(src, dest) < 0) {
		i_fatal("mailbox_rename(%s, %s) failed: %s",
			src_name, dest_name,
			mailbox_get_last_internal_error(src, NULL));
	}
	mailbox_free(&src);
	mailbox_free(&dest);
}

static void test_acl_mailbox_delete(const char *name)
{
	struct mailbox *box = mailbox_alloc(test_acl.list, name, 0);

	if (mailbox_delete(box) < 0) {
		i_fatal("mailbox_delete(%s) failed: %s", name,
			mailbox_get_last_internal_error(box, NULL));
	}
	mailbox_free(&box);
}

/* Reads acl-rights.cache into the backend that the list hook created, so that
   its cache is populated and, within acl_cache_ttl, no longer refreshed. */
static void test_acl_warm_list_backend_cache(void)
{
	struct acl_backend *backend =
		acl_mailbox_list_get_backend(test_acl.list);
	struct acl_mailbox_list_context *ctx =
		acl_backend_nonowner_lookups_iter_init(backend);
	const char *name;

	while (acl_backend_nonowner_lookups_iter_next(ctx, &name)) ;
	test_assert(acl_backend_nonowner_lookups_iter_deinit(&ctx) >= 0);
}

static void test_acl_vfile_rights_cache_rename(void)
{
	const char *cache_path;

	test_begin("acl vfile rights cache rename");
	test_acl_user_init_list_hooks(NULL);
	test_acl_mailbox_create(TEST_MAILBOX);
	cache_path = test_acl_cache_path();

	test_acl_grant_nonowner_lookup(TEST_MAILBOX);
	test_assert(test_acl_cache_has(cache_path, TEST_MAILBOX));

	test_acl_mailbox_rename(TEST_MAILBOX, TEST_MAILBOX2);
	test_assert(test_acl_cache_has(cache_path, TEST_MAILBOX2));
	test_assert(!test_acl_cache_has(cache_path, TEST_MAILBOX));

	test_acl_user_deinit();
	test_end();
}

/* Flags this version doesn't know belong to the mailbox and move with it. */
static void test_acl_vfile_rights_cache_rename_keeps_flags(void)
{
	const char *cache_path;

	test_begin("acl vfile rights cache rename keeps unknown flags");
	test_acl_user_init_list_hooks(NULL);
	test_acl_mailbox_create(TEST_MAILBOX);
	cache_path = test_acl_cache_path();

	test_acl_grant_nonowner_lookup(TEST_MAILBOX);
	test_acl_cache_set_flags(cache_path, TEST_MAILBOX, "xy");

	test_acl_mailbox_rename(TEST_MAILBOX, TEST_MAILBOX2);
	test_assert_strcmp(test_acl_cache_flags(cache_path, TEST_MAILBOX2),
			   "xy");

	test_acl_user_deinit();
	test_end();
}

static void test_acl_vfile_rights_cache_rename_parent(void)
{
	const char *cache_path;

	test_begin("acl vfile rights cache rename parent");
	test_acl_user_init_list_hooks(NULL);
	test_acl_mailbox_create(TEST_MAILBOX);
	test_acl_mailbox_create(TEST_MAILBOX_CHILD);
	cache_path = test_acl_cache_path();

	/* only the child is shared, the renamed parent itself is not */
	test_acl_grant_nonowner_lookup(TEST_MAILBOX_CHILD);
	test_assert(test_acl_cache_has(cache_path, TEST_MAILBOX_CHILD));
	test_assert(!test_acl_cache_has(cache_path, TEST_MAILBOX));

	test_acl_mailbox_rename(TEST_MAILBOX, TEST_MAILBOX2);
	test_assert(test_acl_cache_has(cache_path, TEST_MAILBOX2_CHILD));
	test_assert(!test_acl_cache_has(cache_path, TEST_MAILBOX_CHILD));

	test_acl_user_deinit();
	test_end();
}

static void test_acl_vfile_rights_cache_delete(void)
{
	const char *cache_path;

	test_begin("acl vfile rights cache delete");
	test_acl_user_init_list_hooks(NULL);
	test_acl_mailbox_create(TEST_MAILBOX);
	test_acl_mailbox_create(TEST_MAILBOX2);
	cache_path = test_acl_cache_path();

	test_acl_grant_nonowner_lookup(TEST_MAILBOX);
	test_acl_grant_nonowner_lookup(TEST_MAILBOX2);
	test_assert(test_acl_cache_has(cache_path, TEST_MAILBOX));

	test_acl_mailbox_delete(TEST_MAILBOX);
	test_assert(!test_acl_cache_has(cache_path, TEST_MAILBOX));
	test_assert(test_acl_cache_has(cache_path, TEST_MAILBOX2));

	test_acl_user_deinit();
	test_end();
}

/* Deleting a mailbox leaves its children in place as \NoSelect mailboxes, so
   their entries have to stay too. */
static void test_acl_vfile_rights_cache_delete_child(void)
{
	const char *cache_path;

	test_begin("acl vfile rights cache delete keeps children");
	test_acl_user_init_list_hooks(NULL);
	test_acl_mailbox_create(TEST_MAILBOX);
	test_acl_mailbox_create(TEST_MAILBOX_CHILD);
	cache_path = test_acl_cache_path();

	test_acl_grant_nonowner_lookup(TEST_MAILBOX);
	test_acl_grant_nonowner_lookup(TEST_MAILBOX_CHILD);

	test_acl_mailbox_delete(TEST_MAILBOX);
	test_assert(!test_acl_cache_has(cache_path, TEST_MAILBOX));
	test_assert(test_acl_cache_has(cache_path, TEST_MAILBOX_CHILD));

	test_acl_user_deinit();
	test_end();
}

/* The update has to re-read the file under its lock. An entry another process
   added is invisible to the cached array, and rewriting the file from that
   array would drop it. */
static void test_acl_vfile_rights_cache_rename_rereads_file(void)
{
	const char *cache_path;
	unsigned int count;

	test_begin("acl vfile rights cache rename re-reads the file");
	test_acl_user_init_list_hooks(NULL);
	test_acl_mailbox_create(TEST_MAILBOX);
	cache_path = test_acl_cache_path();

	test_acl_grant_nonowner_lookup(TEST_MAILBOX);
	test_acl_warm_list_backend_cache();

	test_acl_write_file(cache_path,
		t_strconcat(test_acl_read_file(cache_path),
			    "1\tm\t"TEST_MAILBOX3"\n", NULL));

	test_acl_mailbox_rename(TEST_MAILBOX, TEST_MAILBOX2);
	test_assert(test_acl_cache_has(cache_path, TEST_MAILBOX2));
	test_assert(!test_acl_cache_has(cache_path, TEST_MAILBOX));
	test_assert(null_strcmp(test_acl_cache_lookup(cache_path,
						    TEST_MAILBOX3, &count),
				"1.000000") == 0);

	test_acl_user_deinit();
	test_end();
}

/* The mtime field describes the mailbox's own dovecot-acl file, which a
   rename does not touch. Recomputing it would make the next lookup see a
   mismatch and trigger a full rebuild. */
static void test_acl_vfile_rights_cache_rename_keeps_mtime(void)
{
	const char *cache_path, *mtime;
	unsigned int count;

	test_begin("acl vfile rights cache rename keeps the entry mtime");
	test_acl_user_init_list_hooks(NULL);
	test_acl_mailbox_create(TEST_MAILBOX);
	cache_path = test_acl_cache_path();

	test_acl_grant_nonowner_lookup(TEST_MAILBOX);
	mtime = test_acl_cache_lookup(cache_path, TEST_MAILBOX, &count);
	test_assert(mtime != NULL);

	test_acl_mailbox_rename(TEST_MAILBOX, TEST_MAILBOX2);
	test_assert(null_strcmp(test_acl_cache_lookup(cache_path,
						    TEST_MAILBOX2, &count),
				mtime) == 0);

	test_acl_user_deinit();
	test_end();
}

/* A delete leaves no entry behind now, but deployments upgrading to this
   carry dangling entries from before. Renaming onto one has to drop it:
   the first entry found for a name decides whether a rebuild is needed, so
   two entries with differing mtimes trigger one. */
static void test_acl_vfile_rights_cache_rename_onto_dangling(void)
{
	const char *cache_path, *mtime;
	unsigned int count;

	test_begin("acl vfile rights cache rename onto a dangling entry");
	test_acl_user_init_list_hooks(NULL);
	test_acl_mailbox_create(TEST_MAILBOX);
	cache_path = test_acl_cache_path();

	test_acl_grant_nonowner_lookup(TEST_MAILBOX);
	mtime = test_acl_cache_lookup(cache_path, TEST_MAILBOX, &count);
	test_assert(mtime != NULL);

	test_acl_cache_prepend_line(cache_path, "1\tm\t"TEST_MAILBOX2"\n");

	test_acl_mailbox_rename(TEST_MAILBOX, TEST_MAILBOX2);
	test_assert(null_strcmp(test_acl_cache_lookup(cache_path,
						    TEST_MAILBOX2, &count),
				mtime) == 0);
	test_assert(count == 1);

	test_acl_user_deinit();
	test_end();
}

/* Same as renaming onto a dangling entry, but the dangling entry is a child
   of the destination. An exact-match drop would leave two entries for it. */
static void test_acl_vfile_rights_cache_rename_onto_dangling_child(void)
{
	const char *cache_path, *mtime;
	unsigned int count;

	test_begin("acl vfile rights cache rename onto a dangling child entry");
	test_acl_user_init_list_hooks(NULL);
	test_acl_mailbox_create(TEST_MAILBOX);
	test_acl_mailbox_create(TEST_MAILBOX_CHILD);
	cache_path = test_acl_cache_path();

	test_acl_grant_nonowner_lookup(TEST_MAILBOX_CHILD);
	mtime = test_acl_cache_lookup(cache_path, TEST_MAILBOX_CHILD, &count);
	test_assert(mtime != NULL);

	test_acl_cache_prepend_line(cache_path,
		t_strconcat("1\tm\t",
			    mailbox_list_get_storage_name(test_acl.list,
				TEST_MAILBOX2_CHILD), "\n", NULL));

	test_acl_mailbox_rename(TEST_MAILBOX, TEST_MAILBOX2);
	test_assert(null_strcmp(test_acl_cache_lookup(cache_path,
						    TEST_MAILBOX2_CHILD,
						    &count), mtime) == 0);
	test_assert(count == 1);

	test_acl_user_deinit();
	test_end();
}

/* Same as renaming onto a dangling entry, but the destination sorts before
   the source, so the entry to drop comes before the moved one. */
static void test_acl_vfile_rights_cache_rename_onto_earlier_dangling(void)
{
	const char *cache_path, *mtime;
	unsigned int count;

	test_begin("acl vfile rights cache rename onto an earlier dangling entry");
	test_acl_user_init_list_hooks(NULL);
	test_acl_mailbox_create(TEST_MAILBOX2);
	cache_path = test_acl_cache_path();

	test_acl_grant_nonowner_lookup(TEST_MAILBOX2);
	mtime = test_acl_cache_lookup(cache_path, TEST_MAILBOX2, &count);
	test_assert(mtime != NULL);

	test_acl_cache_prepend_line(cache_path, "1\tm\t"TEST_MAILBOX"\n");

	test_acl_mailbox_rename(TEST_MAILBOX2, TEST_MAILBOX);
	test_assert(null_strcmp(test_acl_cache_lookup(cache_path,
						    TEST_MAILBOX, &count),
				mtime) == 0);
	test_assert(count == 1);

	test_acl_user_deinit();
	test_end();
}

/* imapc keeps a secondary list over the same mail root and delegates its
   renames to it, so one RENAME can reach the update twice with the same
   arguments. The second call must not undo the first. */
static void test_acl_vfile_rights_cache_rename_twice(void)
{
	const char *cache_path, *mtime;
	unsigned int count;

	test_begin("acl vfile rights cache rename applied twice");
	test_acl_user_init_list_hooks(NULL);
	test_acl_mailbox_create(TEST_MAILBOX);
	cache_path = test_acl_cache_path();

	test_acl_grant_nonowner_lookup(TEST_MAILBOX);
	mtime = test_acl_cache_lookup(cache_path, TEST_MAILBOX, &count);
	test_assert(mtime != NULL);

	test_acl_mailbox_rename(TEST_MAILBOX, TEST_MAILBOX2);
	test_assert(null_strcmp(test_acl_cache_lookup(cache_path,
						    TEST_MAILBOX2, &count),
				mtime) == 0);

	/* the same rename reported a second time */
	test_assert(acl_backend_nonowner_lookups_rename(test_acl.backend,
		mailbox_list_get_storage_name(test_acl.list, TEST_MAILBOX),
		test_acl.backend,
		mailbox_list_get_storage_name(test_acl.list,
					      TEST_MAILBOX2)) == 0);
	test_assert(null_strcmp(test_acl_cache_lookup(cache_path,
						    TEST_MAILBOX2, &count),
				mtime) == 0);
	test_assert(count == 1);

	test_acl_user_deinit();
	test_end();
}

/* The destination name can have live children while the destination itself
   does not exist. On maildir++ a single directory is renamed, so such a
   rename succeeds, and the children's entries belong to mailboxes the rename
   never touched. */
static void test_acl_vfile_rights_cache_rename_dest_child(void)
{
	const char *cache_path, *mtime;
	unsigned int count;

	test_begin("acl vfile rights cache rename keeps a live destination child");
	test_acl_user_init_list_hooks(NULL);
	test_acl_mailbox_create(TEST_MAILBOX);
	test_acl_mailbox_create(TEST_MAILBOX2_CHILD);
	cache_path = test_acl_cache_path();

	/* only the unrelated destination child is shared */
	test_acl_grant_nonowner_lookup(TEST_MAILBOX2_CHILD);
	mtime = test_acl_cache_lookup(cache_path, TEST_MAILBOX2_CHILD, &count);
	test_assert(mtime != NULL);
	test_acl_grant_nonowner_lookup(TEST_MAILBOX);

	test_acl_mailbox_rename(TEST_MAILBOX, TEST_MAILBOX2);
	test_assert(test_acl_cache_has(cache_path, TEST_MAILBOX2));
	test_assert(null_strcmp(test_acl_cache_lookup(cache_path,
						    TEST_MAILBOX2_CHILD,
						    &count), mtime) == 0);

	test_acl_user_deinit();
	test_end();
}

/* "Boxa" + combining diaeresis, which NFC composes into an a-umlaut. */
#define TEST_MAILBOX_RAW "Boxa\xCC\x88"
#define TEST_MAILBOX_NFC "Box\xC3\xA4"

/* A mailbox whose name is not NFC is renamed on the next ordinary open, with
   no user RENAME involved. That rename allocates the mailbox with
   MAILBOX_FLAG_IGNORE_ACLS, so the plugin's mailbox vfuncs are not installed
   and only the list vfuncs see it. */
static void test_acl_vfile_rights_cache_rename_nfc(void)
{
	const char *cache_path, *vname_new, *error;
	struct mailbox *box;

	test_begin("acl vfile rights cache rename for NFC normalization");
	test_acl_user_init_list_hooks(NULL);

	box = mailbox_alloc(test_acl.list, TEST_MAILBOX_RAW,
			    MAILBOX_FLAG_RAW_NAME);
	box->skip_create_name_restrictions = TRUE;
	if (mailbox_create(box, NULL, FALSE) < 0) {
		i_fatal("mailbox_create(%s) failed: %s", TEST_MAILBOX_RAW,
			mailbox_get_last_internal_error(box, NULL));
	}
	mailbox_free(&box);

	cache_path = test_acl_cache_path();
	test_acl_grant_nonowner_lookup(TEST_MAILBOX_RAW);
	test_assert(test_acl_cache_has(cache_path, TEST_MAILBOX_RAW));

	test_assert(mailbox_rename_nfc_forced(test_acl.list, TEST_MAILBOX_RAW,
					      TEST_MAILBOX_NFC, &vname_new,
					      &error) > 0);
	test_assert(test_acl_cache_has(cache_path, TEST_MAILBOX_NFC));
	test_assert(!test_acl_cache_has(cache_path, TEST_MAILBOX_RAW));

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
		test_acl_vfile_update_own_change_visible,
		test_acl_vfile_rights_cache,
		test_acl_vfile_rights_cache_corrupt,
		test_acl_vfile_rights_cache_rename,
		test_acl_vfile_rights_cache_rename_keeps_flags,
		test_acl_vfile_rights_cache_rename_parent,
		test_acl_vfile_rights_cache_delete,
		test_acl_vfile_rights_cache_delete_child,
		test_acl_vfile_rights_cache_rename_rereads_file,
		test_acl_vfile_rights_cache_rename_keeps_mtime,
		test_acl_vfile_rights_cache_rename_onto_dangling,
		test_acl_vfile_rights_cache_rename_onto_dangling_child,
		test_acl_vfile_rights_cache_rename_onto_earlier_dangling,
		test_acl_vfile_rights_cache_rename_twice,
		test_acl_vfile_rights_cache_rename_dest_child,
		test_acl_vfile_rights_cache_rename_nfc,
		NULL
	};
	int ret;

	test_acl_common_init("test-acl-vfile-update", &argc, &argv);
	ret = test_run(test_functions);
	test_acl_common_deinit();
	return ret;
}
