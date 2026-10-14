/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "master-service.h"
#include "settings.h"
#include "test-common.h"
#include "test-dir.h"
#include "dict.h"
#include "mail-storage.h"
#include "mail-namespace.h"
#include "mail-user.h"
#include "mail-storage-hooks.h"
#include "test-mail-storage-common.h"
#include "acl-api-private.h"
#include "acl-plugin.h"
#include "acl-shared-storage.h"

#include <fcntl.h>
#include <unistd.h>

#define TEST_READER "reader@example.com"
#define TEST_OWNER "owner@example.com"
#define TEST_OWNER_PREFIX "shared/"TEST_OWNER"/"

extern const struct acl_backend_vfuncs acl_backend_vfile;

static const struct mail_storage_hooks test_acl_shared_hooks = {
	.mail_user_created = acl_mail_user_created,
	.mailbox_list_created = acl_mailbox_list_created,
};

static void test_write_sharing_map(const char *path)
{
	const char *content =
		"shared/shared-boxes/user/"TEST_READER"/"TEST_OWNER"\n1\n";
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);

	if (fd == -1)
		i_fatal("open(%s) failed: %m", path);
	if (write(fd, content, strlen(content)) != (ssize_t)strlen(content))
		i_fatal("write(%s) failed: %m", path);
	i_close_fd(&fd);
}

static struct test_mail_storage_ctx *storage;
static struct auth_master_connection *auth_conn;

static struct mail_namespace *test_acl_shared_init(void)
{
	struct mail_namespace *shared_ns;
	const char *map_path;

	storage = test_mail_storage_init();
	io_loop_time_refresh();
	mail_storage_hooks_add_internal(&test_acl_shared_hooks);

	map_path = t_strconcat(test_dir_get(), "/sharing-map", NULL);
	test_write_sharing_map(map_path);

	const char *const extra_input[] = {
		"acl_driver=vfile",
		"mailbox_list_index=no",
		"acl_sharing_map/dict=file",
		"acl_sharing_map/dict/file/dict_driver=file",
		t_strconcat("acl_sharing_map/dict/file/dict_file_path=",
			    map_path, NULL),
		"mail_shared_explicit_inbox=yes",
		"namespace+=shared",
		"namespace/shared/type=shared",
		"namespace/shared/prefix=shared/$user/",
		"namespace/shared/separator=/",
		"namespace/shared/list=children",
		"namespace/shared/mail_driver=maildir",
		t_strconcat("namespace/shared/mail_path=", test_dir_get(),
			    "/%{owner_user}", NULL),
		NULL
	};
	struct test_mail_storage_settings storage_set = {
		.username = TEST_READER,
		.driver = "maildir",
		.hierarchy_sep = "/",
		.extra_input = extra_input,
	};
	test_mail_storage_init_user(storage, &storage_set);
	/* no userdb: owners are looked up without it */
	auth_conn = mail_user_auth_master_conn;
	mail_user_auth_master_conn = NULL;

	shared_ns = mail_namespace_find_prefix(storage->user->namespaces,
					       "shared/");
	i_assert(shared_ns != NULL);
	return shared_ns;
}

static void test_acl_shared_deinit(void)
{
	mail_user_auth_master_conn = auth_conn;
	test_mail_storage_deinit_user(storage);
	mail_storage_hooks_remove_internal(&test_acl_shared_hooks);
	test_mail_storage_deinit(&storage);
}

static void test_acl_shared_new_namespace(void)
{
	struct mail_namespace *shared_ns;

	test_begin("acl shared namespaces add removes empty new namespace");
	shared_ns = test_acl_shared_init();

	/* The owner has no mailboxes visible to us, so the namespace created
	   for the owner is removed again. */
	test_assert(acl_shared_namespaces_add(shared_ns) == 0);
	test_assert(mail_namespace_find_prefix(storage->user->namespaces,
					       TEST_OWNER_PREFIX) == NULL);

	test_acl_shared_deinit();
	test_end();
}

static void test_acl_shared_existing_namespace(void)
{
	struct mail_namespace *shared_ns, *owner_ns;
	struct mailbox *box;

	test_begin("acl shared namespaces add keeps existing namespace");
	shared_ns = test_acl_shared_init();

	/* Opening a mailbox under the owner's prefix creates the owner's
	   namespace, which the mailbox now uses. */
	box = mailbox_alloc(shared_ns->list, TEST_OWNER_PREFIX"box", 0);
	owner_ns = mail_namespace_find_prefix(storage->user->namespaces,
					      TEST_OWNER_PREFIX);
	test_assert(owner_ns != NULL);
	test_assert(box->list->ns == owner_ns);

	/* The owner still has no mailboxes visible to us, but the namespace
	   that was already in use must not be destroyed. */
	test_assert(acl_shared_namespaces_add(shared_ns) == 0);
	test_assert(mail_namespace_find_prefix(storage->user->namespaces,
					       TEST_OWNER_PREFIX) == owner_ns);
	test_assert_strcmp(mailbox_get_namespace(box)->prefix,
			   TEST_OWNER_PREFIX);
	mailbox_free(&box);

	test_acl_shared_deinit();
	test_end();
}

int main(int argc, char **argv)
{
	static void (*const test_functions[])(void) = {
		test_acl_shared_new_namespace,
		test_acl_shared_existing_namespace,
		NULL
	};
	int ret;

	master_service = master_service_init("test-acl-shared",
					     MASTER_SERVICE_FLAG_STANDALONE |
					     MASTER_SERVICE_FLAG_DONT_SEND_STATS |
					     MASTER_SERVICE_FLAG_CONFIG_BUILTIN |
					     MASTER_SERVICE_FLAG_NO_SSL_INIT |
					     MASTER_SERVICE_FLAG_NO_INIT_DATASTACK_FRAME,
					     &argc, &argv, "");
	settings_info_register(&acl_setting_parser_info);
	settings_info_register(&acl_rights_setting_parser_info);
	acl_backend_register(&acl_backend_vfile);
	settings_info_register(&dict_setting_parser_info);
	settings_info_register(&dict_file_setting_parser_info);
	dict_drivers_register_builtin();
	test_dir_init("acl-shared");

	ret = test_run(test_functions);

	dict_drivers_unregister_builtin();
	acl_backend_unregister(acl_backend_vfile.name);
	master_service_deinit(&master_service);
	return ret;
}
