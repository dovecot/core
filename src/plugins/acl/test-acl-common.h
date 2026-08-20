#ifndef TEST_ACL_COMMON_H
#define TEST_ACL_COMMON_H

#include "test-mail-storage-common.h"
#include "acl-api-private.h"

/* The user owning the test storage. */
#define TEST_ACL_OWNER "owner@example.com"
/* A user that is not the owner, for acl_user. */
#define TEST_ACL_USER "reader@example.com"

struct test_acl_ctx {
	struct test_mail_storage_ctx *storage;
	struct mail_user *user;
	struct mailbox_list *list;
	struct acl_backend *backend;
};

extern struct test_acl_ctx test_acl;

/* Initializes master_service and registers the ACL settings and the vfile
   backend. Call from main() before test_run(), and pair with
   test_acl_common_deinit() after it. */
void test_acl_common_init(const char *test_name, int *argc, char **argv[]);
void test_acl_common_deinit(void);

/* Creates a maildir user with the vfile ACL backend and initializes
   test_acl. extra_input is a NULL-terminated list of userdb fields that add
   to or override the defaults, e.g. "acl_user="TEST_ACL_USER. Call these
   from within a test function so that the teardown happens before the test
   framework removes the test directory. */
void test_acl_user_init(const char *const *extra_input);
void test_acl_user_deinit(void);

/* Creates the mailbox unless it already exists. */
void test_acl_mailbox_create(const char *name);
/* Path of the mailbox's local ACL file (vfile backend only), or NULL if the
   mailbox can't have one. */
const char *test_acl_local_path(const char *name);
/* Writes content to path, replacing any existing file. */
void test_acl_write_file(const char *path, const char *content);
/* Returns the contents of path, or NULL if it doesn't exist. */
const char *test_acl_read_file(const char *path);

/* Space-separated rights of the ACL user, in all_mailbox_rights[] order, or
   "<error>" on failure. */
const char *test_acl_my_rights(struct acl_object *aclobj);
/* The object's ACL entries as "<id> <rights>", separated by ", ". Returns
   "<error>" on failure. */
const char *test_acl_list(struct acl_object *aclobj);

#endif
