/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "ioloop.h"
#include "master-service.h"
#include "settings.h"
#include "test-common.h"
#include "test-dir.h"
#include "mail-storage.h"
#include "mail-namespace.h"
#include "mail-storage-hooks.h"
#include "acl-plugin.h"
#include "acl-backend-vfile.h"
#include "test-acl-common.h"

#include <fcntl.h>
#include <unistd.h>

extern const struct acl_backend_vfuncs acl_backend_vfile;

struct test_acl_ctx test_acl;

/* Only the mail_user_created hook is installed. The tests drive the ACL
   backend directly, and the mailbox hooks would additionally ACL-check the
   mailbox_create() calls that the tests use for their own setup. */
static const struct mail_storage_hooks test_acl_storage_hooks = {
	.mail_user_created = acl_mail_user_created,
};

void test_acl_common_init(const char *test_name, int *argc, char **argv[])
{
	master_service = master_service_init(test_name,
					     MASTER_SERVICE_FLAG_STANDALONE |
					     MASTER_SERVICE_FLAG_DONT_SEND_STATS |
					     MASTER_SERVICE_FLAG_CONFIG_BUILTIN |
					     MASTER_SERVICE_FLAG_NO_SSL_INIT |
					     MASTER_SERVICE_FLAG_NO_INIT_DATASTACK_FRAME,
					     argc, argv, "");
	settings_info_register(&acl_setting_parser_info);
	settings_info_register(&acl_rights_setting_parser_info);
	acl_backend_register(&acl_backend_vfile);
	test_dir_init(test_name);
}

void test_acl_common_deinit(void)
{
	acl_backend_unregister(acl_backend_vfile.name);
	master_service_deinit(&master_service);
}

void test_acl_user_init(const char *const *extra_input)
{
	const char *const default_input[] = {
		"acl_driver=vfile",
	};
	ARRAY_TYPE(const_string) input;
	struct mail_namespace *ns;
	const char *error;

	i_zero(&test_acl);
	test_acl.storage = test_mail_storage_init();
	/* the ACL validity cache compares against ioloop_time, which is only
	   updated while the ioloop runs */
	io_loop_time_refresh();
	mail_storage_hooks_add_internal(&test_acl_storage_hooks);

	t_array_init(&input, 8);
	array_append(&input, default_input, N_ELEMENTS(default_input));
	if (extra_input != NULL) {
		array_append(&input, extra_input,
			     str_array_length(extra_input));
	}
	array_append_zero(&input);

	struct test_mail_storage_settings storage_set = {
		.username = TEST_ACL_OWNER,
		.driver = "maildir",
		.hierarchy_sep = "/",
		.extra_input = array_front(&input),
	};
	test_mail_storage_init_user(test_acl.storage, &storage_set);
	test_acl.user = test_acl.storage->user;

	ns = mail_namespace_find_inbox(test_acl.user->namespaces);
	test_acl.list = ns->list;

	int ret = acl_backend_init_auto(test_acl.list, &test_acl.backend,
					&error);
	if (ret <= 0) {
		i_fatal("acl_backend_init_auto() failed: %s", ret < 0 ? error :
			"ACLs are disabled - check acl_driver");
	}

	/* Register the standard rights up front. The cache assigns right
	   indexes in first-seen order and test_acl_my_rights() returns the
	   names in index order, so this keeps the output order stable
	   regardless of what the backend happened to read first. */
	for (unsigned int i = 0; all_mailbox_rights[i] != NULL; i++)
		(void)acl_backend_lookup_right(test_acl.backend,
					       all_mailbox_rights[i]);
}

void test_acl_user_deinit(void)
{
	acl_backend_deinit(&test_acl.backend);
	test_mail_storage_deinit_user(test_acl.storage);
	mail_storage_hooks_remove_internal(&test_acl_storage_hooks);
	test_mail_storage_deinit(&test_acl.storage);
	i_zero(&test_acl);
}

void test_acl_mailbox_create(const char *name)
{
	struct mailbox *box = mailbox_alloc(test_acl.list, name, 0);
	enum mail_error error;

	if (mailbox_create(box, NULL, FALSE) < 0 &&
	    mailbox_get_last_internal_error(box, &error) != NULL &&
	    error != MAIL_ERROR_EXISTS) {
		i_fatal("mailbox_create(%s) failed: %s", name,
			mailbox_get_last_internal_error(box, &error));
	}
	mailbox_free(&box);
}

const char *test_acl_local_path(const char *name)
{
	struct acl_object *aclobj =
		acl_object_init_from_name(test_acl.backend, name);
	struct acl_object_vfile *vaclobj =
		container_of(aclobj, struct acl_object_vfile, aclobj);
	const char *path = t_strdup(vaclobj->local_path);

	acl_object_deinit(&aclobj);
	return path;
}

void test_acl_write_file(const char *path, const char *content)
{
	size_t len = strlen(content);
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);

	if (fd == -1)
		i_fatal("open(%s) failed: %m", path);
	if (write(fd, content, len) != (ssize_t)len)
		i_fatal("write(%s) failed: %m", path);
	i_close_fd(&fd);
}

const char *test_acl_my_rights(struct acl_object *aclobj)
{
	const char *const *rights;

	if (acl_object_get_my_rights(aclobj, pool_datastack_create(),
				     &rights) < 0)
		return "<error>";
	return t_strarray_join(rights, " ");
}

const char *test_acl_list(struct acl_object *aclobj)
{
	struct acl_object_list_iter *iter;
	struct acl_rights rights;
	string_t *str = t_str_new(128);

	iter = acl_object_list_init(aclobj);
	while (acl_object_list_next(iter, &rights)) {
		if (str_len(str) > 0)
			str_append(str, ", ");
		str_append(str, acl_rights_get_id(&rights));
		str_append_c(str, ' ');
		str_append(str, acl_rights_export(&rights));
		if (rights.global)
			str_append(str, " (global)");
	}
	if (acl_object_list_deinit(&iter) < 0)
		return "<error>";
	return str_c(str);
}
