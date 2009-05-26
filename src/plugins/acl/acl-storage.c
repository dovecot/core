/* Copyright (c) 2006-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "mail-namespace.h"
#include "mailbox-list-private.h"
#include "acl-api-private.h"
#include "acl-lookup-dict.h"
#include "acl-plugin.h"

#include <stdlib.h>

struct acl_storage_module acl_storage_module =
	MODULE_CONTEXT_INIT(&mail_storage_module_register);
struct acl_user_module acl_user_module =
	MODULE_CONTEXT_INIT(&mail_user_module_register);

static const char *acl_storage_right_names[ACL_STORAGE_RIGHT_COUNT] = {
	MAIL_ACL_LOOKUP,
	MAIL_ACL_READ,
	MAIL_ACL_WRITE,
	MAIL_ACL_WRITE_SEEN,
	MAIL_ACL_WRITE_DELETED,
	MAIL_ACL_INSERT,
	MAIL_ACL_POST,
	MAIL_ACL_EXPUNGE,
	MAIL_ACL_CREATE,
	MAIL_ACL_DELETE,
	MAIL_ACL_ADMIN
};

void acl_storage_rights_ctx_init(struct acl_storage_rights_context *ctx,
				 struct acl_backend *backend)
{
	unsigned int i;

	ctx->backend = backend;
	for (i = 0; i < ACL_STORAGE_RIGHT_COUNT; i++) {
		ctx->acl_storage_right_idx[i] =
			acl_backend_lookup_right(backend,
						 acl_storage_right_names[i]);
	}
}

int acl_storage_rights_ctx_have_right(struct acl_storage_rights_context *ctx,
				      const char *name, bool parent,
				      unsigned int acl_storage_right_idx,
				      bool *can_see_r)
{
	const unsigned int *idx_arr = ctx->acl_storage_right_idx;
	struct mail_namespace *ns;
	struct acl_object *aclobj;
	int ret, ret2;

	ns = mailbox_list_get_namespace(ctx->backend->list);
	aclobj = !parent ?
		acl_object_init_from_name(ctx->backend, ns->storage, name) :
		acl_object_init_from_parent(ctx->backend, ns->storage, name);
	ret = acl_object_have_right(aclobj, idx_arr[acl_storage_right_idx]);

	if (can_see_r != NULL) {
		ret2 = acl_object_have_right(aclobj,
					     idx_arr[ACL_STORAGE_RIGHT_LOOKUP]);
		if (ret2 < 0)
			ret = -1;
		*can_see_r = ret2 > 0;
	}
	acl_object_deinit(&aclobj);

	return ret;
}

static int
acl_storage_have_right(struct mail_storage *storage, const char *name,
		       unsigned int acl_storage_right_idx, bool *can_see_r)
{
	struct acl_mail_storage *astorage = ACL_CONTEXT(storage);
	int ret;

	ret = acl_storage_rights_ctx_have_right(&astorage->rights, name, FALSE,
						acl_storage_right_idx,
						can_see_r);
	if (ret < 0) 
		mail_storage_set_internal_error(storage);
	return ret;
}

static void acl_storage_destroy(struct mail_storage *storage)
{
	struct acl_mail_storage *astorage = ACL_CONTEXT(storage);

	acl_backend_deinit(&astorage->rights.backend);
	if (astorage->module_ctx.super.destroy != NULL)
		astorage->module_ctx.super.destroy(storage);
}

static struct mailbox *
acl_mailbox_open(struct mail_storage *storage, const char *name,
		 struct istream *input, enum mailbox_open_flags flags)
{
	struct acl_mail_storage *astorage = ACL_CONTEXT(storage);
	struct mailbox *box;
	enum acl_storage_rights save_right;
	bool can_see;
	int ret;

	/* mailbox can be opened either for reading or appending new messages */
	if ((flags & MAILBOX_OPEN_IGNORE_ACLS) != 0) {
		ret = 1;
	} else if ((flags & MAILBOX_OPEN_SAVEONLY) == 0) {
		ret = acl_storage_have_right(storage, name,
					     ACL_STORAGE_RIGHT_READ,
					     &can_see);
	} else {
		save_right = (flags & MAILBOX_OPEN_POST_SESSION) != 0 ?
			ACL_STORAGE_RIGHT_POST : ACL_STORAGE_RIGHT_INSERT;
		ret = acl_storage_have_right(storage, name, save_right,
					     &can_see);
	}
	if (ret <= 0) {
		if (ret < 0)
			return NULL;
		if (can_see) {
			mail_storage_set_error(storage, MAIL_ERROR_PERM,
					       MAIL_ERRSTR_NO_PERMISSION);
		} else {
			mail_storage_set_error(storage, MAIL_ERROR_NOTFOUND,
				T_MAIL_ERR_MAILBOX_NOT_FOUND(name));
		}
		return NULL;
	}

	box = astorage->module_ctx.super.
		mailbox_open(storage, name, input, flags);
	if (box == NULL)
		return NULL;

	return acl_mailbox_open_box(box);
}

static int acl_mailbox_create(struct mail_storage *storage, const char *name,
			      bool directory)
{
	struct acl_mail_storage *astorage = ACL_CONTEXT(storage);
	int ret;

	T_BEGIN {
		ret = acl_storage_rights_ctx_have_right(&astorage->rights, name,
				TRUE, ACL_STORAGE_RIGHT_CREATE, NULL);
	} T_END;

	if (ret <= 0) {
		if (ret == 0) {
			/* Note that if the mailbox didn't have LOOKUP
			   permission, this not reveals to user the mailbox's
			   existence. Can't help it. */
			mail_storage_set_error(storage, MAIL_ERROR_PERM,
					       MAIL_ERRSTR_NO_PERMISSION);
		} else {
			mail_storage_set_internal_error(storage);
		}
		return -1;
	}

	return astorage->module_ctx.super.
		mailbox_create(storage, name, directory);
}

void acl_mail_storage_created(struct mail_storage *storage)
{
	struct acl_user *auser = ACL_USER_CONTEXT(storage->ns->user);
	struct acl_mail_storage *astorage;
	struct acl_backend *backend;

	if (auser == NULL) {
		/* ACLs disabled for this user */
	} else if ((storage->ns->flags & NAMESPACE_FLAG_NOACL) != 0) {
		/* no ACL checks for internal namespaces (lda) */
	} else {
		astorage = p_new(storage->pool, struct acl_mail_storage, 1);
		astorage->module_ctx.super = storage->v;
		storage->v.destroy = acl_storage_destroy;
		storage->v.mailbox_open = acl_mailbox_open;
		storage->v.mailbox_create = acl_mailbox_create;

		backend = acl_mailbox_list_get_backend(mail_storage_get_list(storage));
		acl_storage_rights_ctx_init(&astorage->rights, backend);

		MODULE_CONTEXT_SET(storage, acl_storage_module, astorage);
	}

	if (acl_next_hook_mail_storage_created != NULL)
		acl_next_hook_mail_storage_created(storage);
}

static void acl_user_deinit(struct mail_user *user)
{
	struct acl_user *auser = ACL_USER_CONTEXT(user);

	acl_lookup_dict_deinit(&auser->acl_lookup_dict);
	auser->module_ctx.super.deinit(user);
}

static void acl_mail_user_create(struct mail_user *user, const char *env)
{
	struct acl_user *auser;

	auser = p_new(user->pool, struct acl_user, 1);
	auser->module_ctx.super = user->v;
	user->v.deinit = acl_user_deinit;
	auser->acl_lookup_dict = acl_lookup_dict_init(user);

	auser->acl_env = env;
	auser->master_user = mail_user_plugin_getenv(user, "master_user");

	env = mail_user_plugin_getenv(user, "acl_groups");
	if (env != NULL) {
		auser->groups =
			(const char *const *)p_strsplit(user->pool, env, ",");
	}

	MODULE_CONTEXT_SET(user, acl_user_module, auser);
}

void acl_mail_user_created(struct mail_user *user)
{
	const char *env;

	env = mail_user_plugin_getenv(user, "acl");
	if (env != NULL)
		acl_mail_user_create(user, env);
	else {
		if (user->mail_debug)
			i_info("acl: No acl setting - ACLs are disabled");
	}

	if (acl_next_hook_mail_user_created != NULL)
		acl_next_hook_mail_user_created(user);
}

