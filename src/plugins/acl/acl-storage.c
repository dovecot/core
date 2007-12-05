/* Copyright (c) 2006-2007 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "mail-namespace.h"
#include "mailbox-list-private.h"
#include "acl-api-private.h"
#include "acl-plugin.h"

struct acl_storage_module acl_storage_module =
	MODULE_CONTEXT_INIT(&mail_storage_module_register);

static const char *acl_storage_right_names[ACL_STORAGE_RIGHT_COUNT] = {
	MAIL_ACL_LOOKUP,
	MAIL_ACL_READ,
	MAIL_ACL_WRITE,
	MAIL_ACL_WRITE_SEEN,
	MAIL_ACL_WRITE_DELETED,
	MAIL_ACL_INSERT,
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
				      const char *name,
				      unsigned int acl_storage_right_idx,
				      bool *can_see_r)
{
	const unsigned int *idx_arr = ctx->acl_storage_right_idx;
	struct mail_namespace *ns;
	struct acl_object *aclobj;
	int ret, ret2;

	ns = mailbox_list_get_namespace(ctx->backend->list);
	aclobj = acl_object_init_from_name(ctx->backend, ns->storage, name);
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

	ret = acl_storage_rights_ctx_have_right(&astorage->rights, name,
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
	bool can_see;
	int ret;

	/* mailbox can be opened either for reading or appending new messages */
	if ((flags & MAILBOX_OPEN_SAVEONLY) != 0) {
		ret = acl_storage_have_right(storage, name,
					     ACL_STORAGE_RIGHT_INSERT,
					     &can_see);
	} else {
		ret = acl_storage_have_right(storage, name,
					     ACL_STORAGE_RIGHT_READ,
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
	struct mailbox_list *list = mail_storage_get_list(storage);
	int ret;

	T_FRAME(
		ret = acl_storage_have_right(storage,
			acl_mailbox_list_get_parent_mailbox_name(list, name),
			ACL_STORAGE_RIGHT_CREATE, NULL);
	);

	if (ret <= 0) {
		if (ret == 0) {
			/* Note that if the mailbox didn't have LOOKUP
			   permission, this not reveals to user the mailbox's
			   existence. Can't help it. */
			mail_storage_set_error(storage, MAIL_ERROR_PERM,
					       MAIL_ERRSTR_NO_PERMISSION);
		}
		return -1;
	}

	return astorage->module_ctx.super.
		mailbox_create(storage, name, directory);
}

void acl_mail_storage_created(struct mail_storage *storage)
{
	struct acl_mail_storage *astorage;
	struct acl_backend *backend;

	if (acl_next_hook_mail_storage_created != NULL)
		acl_next_hook_mail_storage_created(storage);

	astorage = p_new(storage->pool, struct acl_mail_storage, 1);
	astorage->module_ctx.super = storage->v;
	storage->v.destroy = acl_storage_destroy;
	storage->v.mailbox_open = acl_mailbox_open;
	storage->v.mailbox_create = acl_mailbox_create;

	backend = acl_mailbox_list_get_backend(mail_storage_get_list(storage));
	acl_storage_rights_ctx_init(&astorage->rights, backend);

	MODULE_CONTEXT_SET(storage, acl_storage_module, astorage);
}

