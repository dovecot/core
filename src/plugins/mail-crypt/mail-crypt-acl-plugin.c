/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop-private.h"
#include "str.h"
#include "sha2.h"
#include "module-dir.h"
#include "var-expand.h"
#include "hex-binary.h"
#include "mail-namespace.h"
#include "mail-storage-hooks.h"
#include "mail-storage-service.h"
#include "acl-plugin.h"
#include "acl-api-private.h"
#include "mail-crypt-common.h"
#include "mail-crypt-key.h"
#include "mail-crypt-plugin.h"

#define MAIL_CRYPT_ACL_LIST_CONTEXT(obj) \
	MODULE_CONTEXT_REQUIRE(obj, mail_crypt_acl_mailbox_list_module)

struct mail_crypt_acl_mailbox_list {
	union mailbox_list_module_context module_ctx;
	struct acl_backend_vfuncs acl_vprev;
};

static MODULE_CONTEXT_DEFINE_INIT(mail_crypt_acl_mailbox_list_module,
				  &mailbox_list_module_register);

void mail_crypt_acl_plugin_init(struct module *module);
void mail_crypt_acl_plugin_deinit(void);

static int
mail_crypt_acl_has_user_read_right(struct acl_object *aclobj,
				   const char *username,
				   const char **error_r)
{
	struct acl_object_list_iter *iter;
	struct acl_rights rights;
	int ret = 0;

	iter = acl_object_list_init(aclobj);
	while (acl_object_list_next(iter, &rights)) {
		if (rights.id_type == ACL_ID_USER &&
		    strcmp(rights.identifier, username) == 0) {
			ret = str_array_find(rights.rights, MAIL_ACL_READ) ? 1 : 0;
			break;
		}
	}
	if (acl_object_list_deinit(&iter) < 0) {
		*error_r = "Failed to iterate ACL objects";
		return -1;
	}

	return ret;
}

static int mail_crypt_acl_has_nonuser_read_right(struct acl_object *aclobj,
						 const char **error_r)
{
	struct acl_object_list_iter *iter;
	struct acl_rights rights;
	int ret = 0;

	iter = acl_object_list_init(aclobj);
	while (acl_object_list_next(iter, &rights)) {
		if (rights.id_type != ACL_ID_USER &&
		    rights.id_type != ACL_ID_OWNER &&
		    rights.rights != NULL &&
		    str_array_find(rights.rights, MAIL_ACL_READ)) {
			ret = 1;
			break;
		}
	}
	if (acl_object_list_deinit(&iter) < 0) {
		*error_r = "Failed to iterate ACL objects";
		return -1;
	}
	return ret;
}

static int
mail_crypt_acl_unset_private_keys(struct mailbox *src_box,
				  const char *dest_user,
				  enum mail_attribute_type type,
				  const char **error_r)
{
	ARRAY_TYPE(const_string) digests;
	const char *error;
	int ret = 1;

	if (mailbox_open(src_box) < 0) {
		*error_r = t_strdup_printf("mail-crypt-acl-plugin: "
					   "mailbox_open(%s) failed: %s",
					   mailbox_get_vname(src_box),
					   mailbox_get_last_internal_error(src_box, NULL));
		return -1;
	}

	t_array_init(&digests, 4);
	if (mail_crypt_box_get_pvt_digests(src_box, pool_datastack_create(),
					   type, &digests, &error) < 0) {
		*error_r = t_strdup_printf("mail-crypt-acl-plugin: "
					   "Failed to lookup public key digests: %s",
					   error);
		mailbox_free(&src_box);
		return -1;
	}

	struct mailbox_transaction_context *t;
	t = mailbox_transaction_begin(src_box, 0, __func__);

	const char *const *hash;
	array_foreach(&digests, hash) {
		const char *ptr;
		/* if the id contains username part, skip to key public id */
		if ((ptr = strchr(*hash, '/')) != NULL)
			ptr++;
		else
			ptr = *hash;
		if ((ret = mail_crypt_box_unset_shared_key(t, ptr, dest_user,
							   error_r)) < 0) {
			ret = -1;
			break;
		}
	}

	if (ret < 0) {
		mailbox_transaction_rollback(&t);
	} else if (mailbox_transaction_commit(&t) < 0) {
		*error_r = t_strdup_printf("mail-crypt-acl-plugin: "
					   "mailbox_transaction_commit(%s) failed: %s",
					   mailbox_get_vname(src_box),
					   mailbox_get_last_internal_error(src_box, NULL));
		return -1;
	}
	return 0;
}

static int
mail_crypt_acl_user_create(struct mail_user *user, const char *dest_username,
			   struct mail_user **dest_user_r,
			   struct mail_storage_service_user **dest_service_user_r,
			   const char **error_r)
{
	const struct mail_storage_service_input *old_input;
	struct mail_storage_service_input input;
	struct mail_storage_service_ctx *service_ctx;
	struct ioloop_context *cur_ioloop_ctx;

	int ret;

	i_assert(user->_service_user != NULL);
	service_ctx = mail_storage_service_user_get_service_ctx(user->_service_user);
	old_input = mail_storage_service_user_get_input(user->_service_user);

	if ((cur_ioloop_ctx = io_loop_get_current_context(current_ioloop)) != NULL)
		io_loop_context_deactivate(cur_ioloop_ctx);

	i_zero(&input);
	input.module = old_input->module;
	input.service = old_input->service;
	input.username = dest_username;
	input.session_id_prefix = user->session_id;
	input.flags_override_add = MAIL_STORAGE_SERVICE_FLAG_NO_PLUGINS |
				   MAIL_STORAGE_SERVICE_FLAG_NO_LOG_INIT;
	input.flags_override_remove = MAIL_STORAGE_SERVICE_FLAG_NO_NAMESPACES;

	ret = mail_storage_service_lookup_next(service_ctx, &input,
						dest_service_user_r,
						dest_user_r, error_r);

	return ret;
}

static int
mail_crypt_acl_update_private_key(struct mailbox *src_box,
				  struct mail_user *dest_user, bool set,
				  bool disallow_insecure,
				  const char **error_r)
{
	struct dcrypt_public_key *key = NULL;
	struct dcrypt_private_key **keyp;
	int ret = 0;

	if (!set) {
		return mail_crypt_acl_unset_private_keys(src_box,
							dest_user->username,
							MAIL_ATTRIBUTE_TYPE_SHARED,
							error_r);
	}

	if (dest_user != NULL) {
		/* get public key from target user */
		if ((ret = mail_crypt_user_get_public_key(dest_user,
							  &key, error_r)) <= 0) {
			if (ret == 0 && disallow_insecure) {
				*error_r = t_strdup_printf("User %s has no active public key",
							   dest_user->username);
				return -1;
			} else if (ret < 0) {
				return -1;
			} else if (ret == 0) {
				/* perform insecure sharing */
				dest_user = NULL;
				key = NULL;
			}
		}
	}

	ARRAY_TYPE(dcrypt_private_key) keys;
	t_array_init(&keys, 8);

	struct mailbox_transaction_context *t =
		mailbox_transaction_begin(src_box, 0, __func__);

	/* get private keys from box */
	if (mail_crypt_box_get_private_keys(src_box, &keys, error_r) < 0 ||
	    mail_crypt_box_share_private_keys(t, key,
					      dest_user == NULL ? NULL :
					      dest_user->username,
					      &keys, error_r) < 0)
		ret = -1;
	if (key != NULL)
		dcrypt_key_unref_public(&key);

	if (ret >= 0) {
		array_foreach_modifiable(&keys, keyp) {
			dcrypt_key_unref_private(keyp);
		}
	}

	if (mailbox_transaction_commit(&t) < 0) {
		*error_r = mailbox_get_last_internal_error(src_box, NULL);
		ret = -1;
	}

	return ret;
}

static int mail_crypt_acl_object_update(struct acl_object *aclobj,
					const struct acl_rights_update *update)
{
	const char *error;
	struct mail_crypt_acl_mailbox_list *mlist =
		MAIL_CRYPT_ACL_LIST_CONTEXT(aclobj->backend->list);
	const char *username;
	struct mail_user *dest_user;
	struct mail_storage_service_user *dest_service_user;
	struct ioloop_context *cur_ioloop_ctx;
	bool have_rights;
	int ret = 0;

	if (mlist->acl_vprev.object_update(aclobj, update) < 0)
		return -1;

	bool disallow_insecure =
		mail_crypt_acl_secure_sharing_enabled(aclobj->backend->list->ns->user);

	const char *box_name = mailbox_list_get_vname(aclobj->backend->list,
						      aclobj->name);
	struct mailbox *box = mailbox_alloc(aclobj->backend->list, box_name, 0);

	switch (update->rights.id_type) {
	case ACL_ID_USER:
		/* setting rights for specific user: we can encrypt the
		   mailbox key for the user. */
		username = update->rights.identifier;
		ret = mail_crypt_acl_has_user_read_right(aclobj, username, &error);

		if (ret < 0) {
			i_error("mail-crypt-acl-plugin: "
				"mail_crypt_acl_has_user_read_right(%s) failed: %s",
				username,
				error);
			break;
		}

		have_rights = ret > 0;

		ret = mail_crypt_acl_user_create(aclobj->backend->list->ns->user,
						 username, &dest_user,
						 &dest_service_user, &error);

		/* to make sure we get correct logging context */
		if (ret > 0)
			mail_storage_service_io_deactivate_user(dest_service_user);
		mail_storage_service_io_activate_user(
			aclobj->backend->list->ns->user->_service_user
		);

		if (ret <= 0) {
			i_error("mail-crypt-acl-plugin: "
				"Cannot initialize destination user %s: %s",
				username, error);
			break;
		} else {
			i_assert(dest_user != NULL);
			if ((ret = mailbox_open(box)) < 0) {
				i_error("mail-crypt-acl-plugin: "
					"mailbox_open(%s) failed: %s",
					mailbox_get_vname(box),
					mailbox_get_last_internal_error(box, NULL));
			} else if ((ret = mail_crypt_acl_update_private_key(box, dest_user,
									have_rights,
									disallow_insecure,
									&error)) < 0) {
				i_error("mail-crypt-acl-plugin: "
					"acl_update_private_key(%s, %s) failed: %s",
					mailbox_get_vname(box),
					username,
					error);
			}
		}

		/* logging context swap again */
		mail_storage_service_io_deactivate_user(
			aclobj->backend->list->ns->user->_service_user
		);
		mail_storage_service_io_activate_user(dest_service_user);

		mail_user_deinit(&dest_user);
		mail_storage_service_user_unref(&dest_service_user);

		if ((cur_ioloop_ctx = io_loop_get_current_context(current_ioloop)) != NULL)
			io_loop_context_deactivate(cur_ioloop_ctx);
		mail_storage_service_io_activate_user(
			aclobj->backend->list->ns->user->_service_user
		);
		break;
	case ACL_ID_OWNER:
		/* we should be the one doing this? ignore */
		break;
	case ACL_ID_ANYONE:
	case ACL_ID_AUTHENTICATED:
	case ACL_ID_GROUP:
	case ACL_ID_GROUP_OVERRIDE:
		if (disallow_insecure) {
			i_error("mail-crypt-acl-plugin: "
				"Secure key sharing is enabled -"
				"Remove or set plugin { %s = no }",
				MAIL_CRYPT_ACL_SECURE_SHARE_SETTING);
			ret = -1;
			break;
		}
		/* the mailbox key needs to be stored unencrypted. for groups
		   we could in theory use per-group encrypted keys, which the
		   users belonging to the group would able to decrypt with
		   their private key, but that becomes quite complicated. */
		if ((ret = mail_crypt_acl_has_nonuser_read_right(aclobj, &error)) < 0) {
		    i_error("mail-crypt-acl-plugin: %s", error);
		} else if ((ret = mailbox_open(box)) < 0) {
			i_error("mail-crypt-acl-plugin: "
				"mailbox_open(%s) failed: %s",
				mailbox_get_vname(box),
				mailbox_get_last_internal_error(box, NULL));
		} else if ((ret = mail_crypt_acl_update_private_key(box,
								    NULL,
								    TRUE,
								    disallow_insecure,
								    &error)) < 0) {
			i_error("mail-crypt-acl-plugin: "
				"acl_update_private_key(%s, %s) failed: %s",
				mailbox_get_vname(box),
				"",
				error);
		}
		break;
	case ACL_ID_TYPE_COUNT:
		i_unreached();
	}

	mailbox_free(&box);
	return ret;
}

static void
mail_crypt_acl_mail_namespace_storage_added(struct mail_namespace *ns)
{
	struct acl_mailbox_list *alist = ACL_LIST_CONTEXT(ns->list);
	struct mail_crypt_acl_mailbox_list *mlist =
		MAIL_CRYPT_ACL_LIST_CONTEXT(ns->list);
	struct acl_backend *backend;

	if (alist == NULL)
		return;

	/* FIXME: this method works only if there's a single plugin doing it.
	   if there are ever multiple plugins hooking into ACL commands the
	   ACL core code would need some changing to make it work correctly. */
	backend = alist->rights.backend;
	mlist->acl_vprev = backend->v;
	backend->v.object_update = mail_crypt_acl_object_update;
}

static void mail_crypt_acl_mailbox_list_deinit(struct mailbox_list *list)
{
	struct mail_crypt_acl_mailbox_list *mlist =
		MAIL_CRYPT_ACL_LIST_CONTEXT(list);

	mlist->module_ctx.super.deinit(list);
}

static void mail_crypt_acl_mailbox_list_created(struct mailbox_list *list)
{
	struct mailbox_list_vfuncs *v = list->vlast;
	struct mail_crypt_acl_mailbox_list *mlist;

	mlist = p_new(list->pool, struct mail_crypt_acl_mailbox_list, 1);
	mlist->module_ctx.super = *v;
	list->vlast = &mlist->module_ctx.super;
	v->deinit = mail_crypt_acl_mailbox_list_deinit;

	MODULE_CONTEXT_SET(list, mail_crypt_acl_mailbox_list_module, mlist);
}

static struct mail_storage_hooks mail_crypt_acl_mail_storage_hooks = {
	.mailbox_list_created = mail_crypt_acl_mailbox_list_created,
	.mail_namespace_storage_added = mail_crypt_acl_mail_namespace_storage_added
};

void mail_crypt_acl_plugin_init(struct module *module)
{
	mail_storage_hooks_add(module, &mail_crypt_acl_mail_storage_hooks);
}

void mail_crypt_acl_plugin_deinit(void)
{
	mail_storage_hooks_remove(&mail_crypt_acl_mail_storage_hooks);
}

const char *mail_crypt_acl_plugin_dependencies[] = { "acl", NULL };
