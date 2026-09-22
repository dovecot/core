/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "mail-namespace.h"
#include "mailbox-list-private.h"
#include "acl-api-private.h"
#include "acl-lookup-dict.h"
#include "acl-plugin.h"


struct acl_storage_module acl_storage_module =
	MODULE_CONTEXT_INIT(&mail_storage_module_register);
struct acl_user_module acl_user_module =
	MODULE_CONTEXT_INIT(&mail_user_module_register);

static void acl_user_deinit(struct mail_user *user)
{
	struct acl_user *auser = ACL_USER_CONTEXT(user);

	i_assert(auser != NULL);
	acl_lookup_dict_deinit(&auser->acl_lookup_dict);
	auser->module_ctx.super.deinit(user);
}

void acl_mail_user_created(struct mail_user *user)
{
	struct mail_user_vfuncs *v = user->vlast;
	struct acl_user *auser;
	const char *error;
	int ret;

	auser = p_new(user->pool, struct acl_user, 1);
	auser->module_ctx.super = *v;
	user->vlast = &auser->module_ctx.super;
	v->deinit = acl_user_deinit;
	if ((ret = acl_lookup_dict_init(user, &auser->acl_lookup_dict, &error)) < 0) {
		e_error(user->event, "acl: dict_init() failed: %s", error);
		user->error = p_strdup(user->pool, error);
	} else if (ret == 0) {
		e_debug(user->event, "acl: Shared mailbox listing disabled: %s", error);
	} else {
		e_debug(user->event, "acl: Shared mailbox listing enabled");
	}

	MODULE_CONTEXT_SET(user, acl_user_module, auser);
}

bool acl_backend_get_root_dir(struct acl_backend *backend,
			      const char **root_dir_r,
			      enum mailbox_list_path_type *type_r)
{
	struct mail_storage *storage;
	const char *rootdir, *maildir;
	enum mailbox_list_path_type type;

	if (backend->set->acl_globals_only)
		return FALSE;

	storage = mailbox_list_get_namespace(backend->list)->storage;
	if (storage == NULL) {
		/* Not known yet - the ACL backend is initialized from the
		   mailbox_list_created hook, before the namespace's storage
		   is created. */
		return FALSE;
	}
	type = mail_storage_get_acl_list_path_type(storage);
	if (!mailbox_list_get_root_path(backend->list, type, &rootdir))
		return FALSE;
	*type_r = type;

	if (type == MAILBOX_LIST_PATH_TYPE_DIR &&
	    mail_storage_is_mailbox_file(storage)) {
		maildir = mailbox_list_get_root_forced(
			backend->list, MAILBOX_LIST_PATH_TYPE_MAILBOX);
		if (strcmp(maildir, rootdir) == 0) {
			/* acl-rights.cache would show up as a mailbox if we
			   created it to root dir. since we don't really have
			   any other good alternatives, place it to control
			   dir */
			rootdir = mailbox_list_get_root_forced(backend->list,
					MAILBOX_LIST_PATH_TYPE_CONTROL);
			*type_r = MAILBOX_LIST_PATH_TYPE_CONTROL;
		}
	}
	*root_dir_r = rootdir;
	return TRUE;
}

bool acl_backend_storage_has_cached_files(struct acl_backend *backend)
{
	struct mail_storage *storage =
		mailbox_list_get_namespace(backend->list)->storage;

	return (storage->class_flags &
		MAIL_STORAGE_CLASS_FLAG_CACHED_FILES) != 0;
}

enum mailbox_list_path_type
mail_storage_get_acl_list_path_type(struct mail_storage *storage)
{
	if (mail_storage_is_mailbox_file(storage)) {
		/* mailbox is a directory (e.g. mbox) */
		return MAILBOX_LIST_PATH_TYPE_CONTROL;
	}
	if ((storage->class_flags & MAIL_STORAGE_CLASS_FLAG_NO_ROOT) != 0) {
		/* there is no local mailbox directory */
		return MAILBOX_LIST_PATH_TYPE_CONTROL;
	}
	return MAILBOX_LIST_PATH_TYPE_MAILBOX;
}
