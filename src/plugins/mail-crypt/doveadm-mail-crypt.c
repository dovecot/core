/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "askpass.h"
#include "doveadm-mail.h"
#include "getopt.h"
#include "array.h"
#include "str.h"
#include "buffer.h"
#include "ioloop.h"
#include "ioloop-private.h"
#include "mail-namespace.h"
#include "mail-storage.h"
#include "mail-storage-settings.h"
#include "mailbox-attribute.h"
#include "mail-crypt-common.h"
#include "mail-crypt-key.h"
#include "mailbox-list-iter.h"
#include "doveadm-print.h"
#include "hex-binary.h"

#define DOVEADM_MCP_SUCCESS "\xE2\x9C\x93" /* emits a utf-8 CHECK MARK (U+2713) */
#define DOVEADM_MCP_FAIL "x"
#define DOVEADM_MCP_USERKEY "<userkey>"

struct generated_key {
	const char *name;
	const char *id;
	const char *error;
	struct mailbox *box;
	bool success:1;
	bool active:1;
};

ARRAY_DEFINE_TYPE(generated_keys, struct generated_key);

struct mcp_cmd_context {
	struct doveadm_mail_cmd_context ctx;

	const char *old_password;
	const char *new_password;

	unsigned int matched_keys;

	bool userkey_only:1;
	bool recrypt_box_keys:1;
	bool force:1;
	bool ask_old_password:1;
	bool ask_new_password:1;
	bool clear_password:1;
};

struct mcp_key_iter_ctx {
	pool_t pool;
	ARRAY_TYPE(generated_keys) keys;
};

void doveadm_mail_crypt_plugin_init(struct module *mod ATTR_UNUSED);
void doveadm_mail_crypt_plugin_deinit(void);

static int
mcp_user_create(struct mail_user *user, const char *dest_username,
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

	ret = mail_storage_service_lookup_next(service_ctx, &input,
						dest_service_user_r,
						dest_user_r, error_r);

	if (ret == 0)
		*error_r = "User not found";

	return ret;
}

static int
mcp_update_shared_key(struct mailbox_transaction_context *t,
		      struct mail_user *user, const char *target_uid,
		      struct dcrypt_private_key *key, const char **error_r)
{
	const char *error;
	struct mail_user *dest_user;
	struct mail_storage_service_user *dest_service_user;
	struct ioloop_context *cur_ioloop_ctx;
	struct dcrypt_public_key *pkey;
	const char *dest_username;
	int ret = 0;

	bool disallow_insecure = mail_crypt_acl_secure_sharing_enabled(user);

	ret = mcp_user_create(user, target_uid, &dest_user,
			      &dest_service_user, &error);

	/* to make sure we get correct logging context */
	if (ret > 0)
		mail_storage_service_io_deactivate_user(dest_service_user);
	mail_storage_service_io_activate_user(user->_service_user);

	if (ret <= 0) {
		i_error("Cannot initialize destination user %s: %s",
			target_uid, error);
		return ret;
	} else {
		i_assert(dest_user != NULL);
		dest_username = dest_user->username;

		/* get public key from target user */
		if ((ret = mail_crypt_user_get_public_key(dest_user,
							  &pkey, error_r)) <= 0) {
			if (ret == 0 && disallow_insecure) {
				*error_r = t_strdup_printf("User %s has no active public key",
							   dest_user->username);
				ret = -1;
			} else if (ret == 0) {
				/* perform insecure sharing */
				dest_username = NULL;
				pkey = NULL;
				ret = 1;
			}
		}

		if (ret == 1) {
			ARRAY_TYPE(dcrypt_private_key) keys;
			t_array_init(&keys, 1);
			array_push_back(&keys, &key);
			ret = mail_crypt_box_share_private_keys(t, pkey,
								dest_username,
								&keys, error_r);
		}
		
	}

	/* logging context swap again */
	mail_storage_service_io_deactivate_user(user->_service_user);
	mail_storage_service_io_activate_user(dest_service_user);

	mail_user_unref(&dest_user);
	mail_storage_service_user_unref(&dest_service_user);

	if ((cur_ioloop_ctx = io_loop_get_current_context(current_ioloop)) != NULL)
		io_loop_context_deactivate(cur_ioloop_ctx);

	mail_storage_service_io_activate_user(user->_service_user);

	return ret;
}

static int mcp_update_shared_keys(struct mailbox *box, struct mail_user *user,
				  const char *pubid, struct dcrypt_private_key *key)
{
	const char *error;
	int ret;

	ARRAY_TYPE(const_string) ids;
	t_array_init(&ids, 8);

	/* figure out who needs the key */
	if ((ret = mail_crypt_box_get_pvt_digests(box, pool_datastack_create(),
						  MAIL_ATTRIBUTE_TYPE_SHARED,
					     	  &ids, &error)) < 0) {
		i_error("mail_crypt_box_get_pvt_digests(%s, /shared) failed: %s",
			mailbox_get_vname(box),
			error);
		return -1;
	}

	const char *const *id;
	bool found = FALSE;
	string_t *uid = t_str_new(64);

	struct mailbox_transaction_context *t =
		mailbox_transaction_begin(box, 0, __func__);
	
	ret = 0;

	/* then perform sharing */
	array_foreach(&ids, id) {
		if (strchr(*id, '/') != NULL) {
			str_truncate(uid, 0);
			const char *hexuid = t_strcut(*id, '/');
			hex_to_binary(hexuid, uid);
			if (mcp_update_shared_key(t, user, str_c(uid), key,
						  &error) < 0) {
				i_error("mcp_update_shared_key(%s, %s) failed: %s",
					mailbox_get_vname(box),
					str_c(uid),
					error);
				ret = -1;
				break;
			}
		} else if (!found) {
			found = TRUE;
			if (mail_crypt_box_set_shared_key(t, pubid, key,
							  NULL, NULL,
							  &error) < 0) {
				i_error("mail_crypt_box_set_shared_key(%s) failed: %s",
					mailbox_get_vname(box),
					error);
				ret = -1;
				break;
			}
		}
	}

	if (ret < 0) {
		mailbox_transaction_rollback(&t);
	} else if (mailbox_transaction_commit(&t) < 0) {
		i_error("mailbox_transaction_commit(%s) failed: %s",
			mailbox_get_vname(box),
			error);
		ret = -1;
	}

	return ret;
}

static int mcp_keypair_generate(struct mcp_cmd_context *ctx,
				struct dcrypt_public_key *user_key,
				struct mailbox *box, struct dcrypt_keypair *pair_r,
				const char **pubid_r, const char **error_r)
{
	struct dcrypt_keypair pair = {NULL, NULL};

	int ret;

	if ((ret = mail_crypt_box_get_public_key(box, &pair.pub, error_r)) < 0) {
		ret = -1;
	} else if (ret == 1 && !ctx->force) {
		i_info("Folder key exists. Use -f to generate a new one");
		buffer_t *key_id = t_str_new(MAIL_CRYPT_HASH_BUF_SIZE);
		const char *error;
		if (!dcrypt_key_id_public(pair.pub,
					MAIL_CRYPT_KEY_ID_ALGORITHM,
					key_id, &error)) {
			i_error("dcrypt_key_id_public() failed: %s",
				error);
			return -1;
		}
		*pubid_r = p_strdup(ctx->ctx.pool, binary_to_hex(key_id->data,
								 key_id->used));
		*pair_r = pair;
		return 1;
	} else if (ret == 1 && ctx->recrypt_box_keys) {
		/* do nothing, because force isn't being used *OR*
		   we are recrypting box keys and force refers to
		   user keypair.

		   FIXME: this could be less confusing altogether */
		ret = 0;
	} else {
		if ((ret = mail_crypt_box_generate_keypair(box, &pair,
						user_key, pubid_r, error_r)) < 0) {
			ret = -1;
		} else {
			*pubid_r = p_strdup(ctx->ctx.pool, *pubid_r);
			*pair_r = pair;
			return 1;
		}
	}

	if (pair.pub != NULL)
		dcrypt_key_unref_public(&pair.pub);
	if (pair.priv != NULL)
		dcrypt_key_unref_private(&pair.priv);

	return ret;
}

static int mcp_keypair_generate_run(struct doveadm_mail_cmd_context *_ctx,
				    struct mail_user *user,
				    ARRAY_TYPE(generated_keys) *result)
{
	const char *error;
	int ret;
	struct dcrypt_public_key *user_key;
	struct mcp_cmd_context *ctx =
		(struct mcp_cmd_context *)_ctx;
	const char *pubid;
	bool user_key_generated = FALSE;
	struct generated_key *res;

	if ((ret = mail_crypt_user_get_public_key(user, &user_key,
						  &error)) <= 0) {
		struct dcrypt_keypair pair;
		if (ret < 0) {
			i_error("mail_crypt_user_get_public_key(%s) failed: %s",
				user->username,
				error);
		} else if (mail_crypt_user_generate_keypair(user, &pair,
							     &pubid, &error) < 0) {
			ret = -1;
			i_error("mail_crypt_user_generate_keypair(%s) failed: %s",
				user->username,
				error);
			res = array_append_space(result);
			res->name = "";
			res->error = p_strdup(_ctx->pool, error);
			res->success = FALSE;
		} else {
			res = array_append_space(result);
			res->name = DOVEADM_MCP_USERKEY;
			res->id = p_strdup(_ctx->pool, pubid);
			res->success = TRUE;
			/* don't do it again later on */
			user_key_generated = TRUE;
			ret = 1;
			user_key = pair.pub;
			dcrypt_key_unref_private(&pair.priv);
		}
		if (ret < 0) return ret;
		ctx->matched_keys++;
	}
	if (ret == 1 && ctx->userkey_only && !user_key_generated) {
		if (!ctx->force) {
			i_info("userkey exists. Use -f to generate a new one");
			buffer_t *key_id = t_str_new(MAIL_CRYPT_HASH_BUF_SIZE);
			if (!dcrypt_key_id_public(user_key,
						MAIL_CRYPT_KEY_ID_ALGORITHM,
						key_id, &error)) {
				i_error("dcrypt_key_id_public() failed: %s",
					error);
				dcrypt_key_unref_public(&user_key);
				return -1;
			}
			const char *hash = binary_to_hex(key_id->data,
							 key_id->used);
			res = array_append_space(result);
			res->name = DOVEADM_MCP_USERKEY;
			res->id = p_strdup(_ctx->pool, hash);
			res->success = TRUE;
			ctx->matched_keys++;
			dcrypt_key_unref_public(&user_key);
			return 1;
		}
		struct dcrypt_keypair pair;
		dcrypt_key_unref_public(&user_key);
		/* regen user key */
		res = array_append_space(result);
		res->name = DOVEADM_MCP_USERKEY;
		if (mail_crypt_user_generate_keypair(user, &pair, &pubid,
						     &error) < 0) {
			res->success = FALSE;
			res->error = p_strdup(_ctx->pool, error);
			return -1;
		}
		res->success = TRUE;
		res->id = p_strdup(_ctx->pool, pubid);
		user_key = pair.pub;
		dcrypt_key_unref_private(&pair.priv);
		ctx->matched_keys++;
	}

	if (ctx->userkey_only) {
		dcrypt_key_unref_public(&user_key);
		return 0;
	}

	const char *const *patterns = (const char *const[]){ "*", NULL };

	/* only re-encrypt all folder keys if wanted */
	if (!ctx->recrypt_box_keys) {
		patterns = ctx->ctx.args;
	}

	const struct mailbox_info *info;
	struct mailbox_list_iterate_context *iter =
		mailbox_list_iter_init_namespaces(user->namespaces,
				 		  patterns,
						  MAIL_NAMESPACE_TYPE_PRIVATE,
			 			  MAILBOX_LIST_ITER_SKIP_ALIASES |
						  MAILBOX_LIST_ITER_NO_AUTO_BOXES |
						  MAILBOX_LIST_ITER_RETURN_NO_FLAGS);
	while((info = mailbox_list_iter_next(iter)) != NULL) {
		if ((info->flags & MAILBOX_NOSELECT) != 0 ||
		    (info->flags & MAILBOX_NONEXISTENT) != 0) continue;
		struct dcrypt_keypair pair;

		struct mailbox *box =
			mailbox_alloc(info->ns->list,
				      info->vname, 0);
		if (mailbox_open(box) < 0) {
			res = array_append_space(result);
			res->name = p_strdup(_ctx->pool, info->vname);
			res->success = FALSE;
			res->error = p_strdup(_ctx->pool,
					mailbox_get_last_internal_error(box, NULL));
		} else if ((ret = mcp_keypair_generate(ctx, user_key, box,
							&pair, &pubid,
							&error)) < 0) {
			res = array_append_space(result);
			res->name = p_strdup(_ctx->pool, info->vname);
			res->success = FALSE;
			res->error = p_strdup(_ctx->pool, error);
		} else if (ret == 0) {
			/* nothing happened because key already existed and
			   force wasn't used, skip */
		} else if (ret > 0) {
			res = array_append_space(result);
			res->name = p_strdup(_ctx->pool, info->vname);
			res->success = TRUE;
			res->id = pubid;
			T_BEGIN {
				mcp_update_shared_keys(box, user, pubid, pair.priv);
			} T_END;
			if (pair.pub != NULL)
				dcrypt_key_unref_public(&pair.pub);
			if (pair.priv != NULL)
				dcrypt_key_unref_private(&pair.priv);
			ctx->matched_keys++;
		}
		mailbox_free(&box);
	}

	(void)mailbox_list_iter_deinit(&iter);

	dcrypt_key_unref_public(&user_key);
	return 0;
}

static int cmd_mcp_keypair_generate_run(struct doveadm_mail_cmd_context *_ctx,
					struct mail_user *user)
{
	struct mcp_cmd_context *ctx =
		(struct mcp_cmd_context *)_ctx;

	int ret = 0;

	ARRAY_TYPE(generated_keys) result;
	p_array_init(&result, _ctx->pool, 8);

	if (mcp_keypair_generate_run(_ctx, user, &result) < 0)
		_ctx->exit_code = EX_DATAERR;

	doveadm_print_init(DOVEADM_PRINT_TYPE_TABLE);
	doveadm_print_header("success", "  ", 0);
	doveadm_print_header("box", "Folder", 0);
	doveadm_print_header("pubid", "Public ID", 0);

	const struct generated_key *res;

	array_foreach(&result, res) {
		if (res->success)
			doveadm_print(DOVEADM_MCP_SUCCESS);
		else {
			_ctx->exit_code = EX_DATAERR;
			ret = -1;
			doveadm_print(DOVEADM_MCP_FAIL);
		}
		doveadm_print(res->name);
		if (!res->success)
			doveadm_print(t_strdup_printf("ERROR: %s", res->error));
		else
			doveadm_print(res->id);
	}

	if (ctx->matched_keys == 0)
		i_warning("mailbox cryptokey generate: Nothing was matched. "
			  "Use -U or specify mask?");
	return ret;
}

static void mcp_key_list(struct mcp_cmd_context *ctx,
			struct mail_user *user,
			void(*callback)(const struct generated_key *, void *),
			void *context)
{
	const char *error;
	int ret;

	/* we need to use the mailbox attribute API here, as we
	   are not necessarily able to decrypt any of these keys
	*/

	ARRAY_TYPE(const_string) ids;
	t_array_init(&ids, 8);

	if (ctx->userkey_only) {
		struct mailbox_attribute_iter *iter;
		struct mail_namespace *ns =
			mail_namespace_find_inbox(user->namespaces);
		struct mailbox *box =
			mailbox_alloc(ns->list, "INBOX", MAILBOX_FLAG_READONLY);
		struct mail_attribute_value value;
		i_zero(&value);

		if ((ret = mailbox_attribute_get(box, MAIL_ATTRIBUTE_TYPE_SHARED,
						 USER_CRYPT_PREFIX
						 ACTIVE_KEY_NAME,
						 &value)) < 0) {
			i_error("mailbox_get_attribute(%s, %s) failed: %s",
				mailbox_get_vname(box),
				USER_CRYPT_PREFIX ACTIVE_KEY_NAME,
				mailbox_get_last_internal_error(box, NULL));
		}

		iter = mailbox_attribute_iter_init(box,
						   MAIL_ATTRIBUTE_TYPE_PRIVATE,
					  	   USER_CRYPT_PREFIX
						   PRIVKEYS_PREFIX);
		const char *key_id;
		if (value.value == NULL)
			value.value = "<NO ACTIVE KEY>";
		while ((key_id = mailbox_attribute_iter_next(iter)) != NULL) {
			struct generated_key key;
			key.id = key_id;
			key.active = strcmp(value.value, key_id) == 0;
			key.name = "";
			key.box = box;
			callback(&key, context);
			ctx->matched_keys++;
		}
		if (mailbox_attribute_iter_deinit(&iter) < 0)
			i_error("mailbox_attribute_iter_deinit(%s) failed: %s",
				mailbox_get_vname(box),
				mailbox_get_last_internal_error(box, NULL));
		mailbox_free(&box);
		return;
	}

	const struct mailbox_info *info;
	struct mailbox_list_iterate_context *iter =
		mailbox_list_iter_init_namespaces(user->namespaces,
						  ctx->ctx.args,
						  MAIL_NAMESPACE_TYPE_PRIVATE,
						  MAILBOX_LIST_ITER_SKIP_ALIASES |
						  MAILBOX_LIST_ITER_NO_AUTO_BOXES |
						  MAILBOX_LIST_ITER_RETURN_NO_FLAGS);

	while((info = mailbox_list_iter_next(iter)) != NULL) {
		if ((info->flags & MAILBOX_NOSELECT) != 0 ||
		    (info->flags & MAILBOX_NONEXISTENT) != 0) continue;

		struct mailbox *box =
			mailbox_alloc(info->ns->list,
				      info->vname, MAILBOX_FLAG_READONLY);
		struct mail_attribute_value value;
		i_zero(&value);
		array_clear(&ids);

		/* get active ID */
		if ((ret = mailbox_attribute_get(box, MAIL_ATTRIBUTE_TYPE_SHARED,
					  	 BOX_CRYPT_PREFIX
						 ACTIVE_KEY_NAME,
						 &value)) < 0) {
			i_error("mailbox_get_attribute(%s, %s) failed: %s",
				mailbox_get_vname(box),
				BOX_CRYPT_PREFIX ACTIVE_KEY_NAME,
				mailbox_get_last_internal_error(box, NULL));
		} else if ((ret = mail_crypt_box_get_pvt_digests(box, pool_datastack_create(),
								 MAIL_ATTRIBUTE_TYPE_PRIVATE,
							   	 &ids, &error)) < 0) {
			i_error("mail_crypt_box_get_pvt_digests(%s) failed: %s",
				mailbox_get_vname(box),
				error);
		} else {
			const char *const *id;
			const char *boxname = mailbox_get_vname(box);
			if (value.value == NULL)
				value.value = "<NO ACTIVE KEY>";
			array_foreach(&ids, id) {
				struct generated_key key;
				key.name = boxname;
				key.id = *id;
				if (value.value != NULL)
					key.active = strcmp(*id, value.value) == 0;
				else
					key.active = FALSE;
				key.box = box;
				callback(&key, context);
				ctx->matched_keys++;
			}
		}
		mailbox_free(&box);
	}

	(void)mailbox_list_iter_deinit(&iter);
}

static void cmd_mcp_key_list_cb(const struct generated_key *_key, void *context)
{
	struct mcp_key_iter_ctx *ctx = context;
	struct generated_key *key = array_append_space(&ctx->keys);
	key->name = p_strdup(ctx->pool, _key->name);
	key->id = p_strdup(ctx->pool, _key->id);
	key->active = _key->active;
}

static int cmd_mcp_key_list_run(struct doveadm_mail_cmd_context *_ctx,
				struct mail_user *user)
{
	struct mcp_cmd_context *ctx =
		(struct mcp_cmd_context *)_ctx;
	struct mcp_key_iter_ctx iter_ctx;
	i_zero(&iter_ctx);
	iter_ctx.pool = _ctx->pool;
	p_array_init(&iter_ctx.keys, _ctx->pool, 8);

	mcp_key_list(ctx, user, cmd_mcp_key_list_cb, &iter_ctx);

	doveadm_print_init(DOVEADM_PRINT_TYPE_TABLE);
	doveadm_print_header("box", "Folder", 0);
	doveadm_print_header("active", "Active", 0);
	doveadm_print_header("pubid", "Public ID", 0);

	const struct generated_key *key;
	array_foreach(&iter_ctx.keys, key) {
		doveadm_print(key->name);
		doveadm_print(key->active ? "yes" : "no");
		doveadm_print(key->id);
	}

	if (ctx->matched_keys == 0)
		i_warning("mailbox cryptokey list: Nothing was matched. "
			  "Use -U or specify mask?");

	return 0;
}

static void cmd_mcp_key_export_cb(const struct generated_key *key,
				  void *context ATTR_UNUSED)
{
	struct dcrypt_private_key *pkey;
	bool user_key = FALSE;
	const char *error = NULL;
	int ret;

	if (*key->name == '\0')
		user_key = TRUE;

	doveadm_print(key->name);
	doveadm_print(key->id);

	if ((ret = mail_crypt_get_private_key(key->box, key->id, user_key, FALSE,
					      &pkey, &error)) <= 0) {
		if (ret == 0)
			error = "key not found";
		doveadm_print(t_strdup_printf("ERROR: %s", error));
		doveadm_print("");
	} else {
		string_t *out = t_str_new(64);
		if (!dcrypt_key_store_private(pkey, DCRYPT_FORMAT_PEM, NULL, out,
					      NULL, NULL, &error)) {
			doveadm_print(t_strdup_printf("ERROR: %s", error));
			doveadm_print("");
		} else {
			/* this is to make it more compatible with openssl cli
			   as it expects BEGIN on it's own line */
			doveadm_print(t_strdup_printf("\n%s", str_c(out)));
		}
		dcrypt_key_unref_private(&pkey);
	}
}

static int cmd_mcp_key_export_run(struct doveadm_mail_cmd_context *_ctx,
				  struct mail_user *user)
{
	struct mcp_cmd_context *ctx =
		(struct mcp_cmd_context *)_ctx;

	doveadm_print_init(DOVEADM_PRINT_TYPE_PAGER);
	doveadm_print_header("box", "Folder", 0);
	doveadm_print_header("name", "Public ID", 0);
	doveadm_print_header("error", "Error", 0);
	doveadm_print_header("key", "Key", 0);

	mcp_key_list(ctx, user, cmd_mcp_key_export_cb, NULL);

	return 0;
}

static int cmd_mcp_key_password_run(struct doveadm_mail_cmd_context *_ctx,
				    struct mail_user *user)
{
	struct mcp_cmd_context *ctx =
		(struct mcp_cmd_context *)_ctx;
	bool cli = (_ctx->cctx->conn_type == DOVEADM_CONNECTION_TYPE_CLI);

	struct raw_key {
		const char *attr;
		const char *id;
		const char *data;
	};

	ARRAY(struct raw_key) raw_keys;

	doveadm_print_init(DOVEADM_PRINT_TYPE_PAGER);

	doveadm_print_header_simple("result");

	if (ctx->ask_old_password) {
		if (ctx->old_password != NULL) {
			doveadm_print("old password specified, cannot ask for it");
			_ctx->exit_code = EX_USAGE;
			return -1;
		}
		if (!cli) {
			doveadm_print("No cli - cannot ask for password");
			_ctx->exit_code = EX_USAGE;
			return -1;
		}
		ctx->old_password =
			p_strdup(_ctx->pool, t_askpass("Old password: "));
	}

	if (ctx->ask_new_password) {
		if (ctx->new_password != NULL) {
			doveadm_print("new password specified, cannot ask for it");
			_ctx->exit_code = EX_USAGE;
			return -1;
		}
		if (!cli) {
			doveadm_print("No cli - cannot ask for password");
			_ctx->exit_code = EX_USAGE;
			return -1;
		}
		ctx->new_password =
			p_strdup(_ctx->pool, t_askpass("New password: "));
	}

	if (ctx->clear_password &&
	    (ctx->new_password != NULL ||
	     mail_user_plugin_getenv(user, MAIL_CRYPT_USERENV_PASSWORD) != NULL)) {
		doveadm_print("clear password and new password specified");
		_ctx->exit_code = EX_USAGE;
		return -1;
	}

	struct mail_namespace *ns = mail_namespace_find_inbox(user->namespaces);
	struct mailbox *box = mailbox_alloc(ns->list, "INBOX", 0);
	if (mailbox_open(box) < 0) {
		doveadm_print(t_strdup_printf("mailbox_open(%s) failed: %s",
			mailbox_get_vname(box),
			mailbox_get_last_internal_error(box, NULL)));
		_ctx->exit_code = EX_TEMPFAIL;
		return -1;
	}

	t_array_init(&raw_keys, 8);

	/* then get the current user keys, all of them */
	struct mailbox_attribute_iter *iter =
		mailbox_attribute_iter_init(box,
					    MAIL_ATTRIBUTE_TYPE_PRIVATE,
					    USER_CRYPT_PREFIX
					    PRIVKEYS_PREFIX);
	const char *error;
	const char *key_id;
	int ret = 1;
	unsigned int count = 0;

	while ((key_id = mailbox_attribute_iter_next(iter)) != NULL) {
		const char *attr =
			t_strdup_printf(USER_CRYPT_PREFIX PRIVKEYS_PREFIX "%s",
					key_id);

		struct mail_attribute_value value;
		if ((ret = mailbox_attribute_get(box, MAIL_ATTRIBUTE_TYPE_PRIVATE,
						 attr, &value)) < 0) {
			doveadm_print(t_strdup_printf("mailbox_attribute_get(%s, %s) failed: %s",
				mailbox_get_vname(box), attr,
				mailbox_get_last_internal_error(box, NULL)));
			_ctx->exit_code = EX_TEMPFAIL;
			break;
		} else if (ret > 0) {
			struct raw_key *raw_key = array_append_space(&raw_keys);
			raw_key->attr = p_strdup(_ctx->pool, attr);
			raw_key->id = p_strdup(_ctx->pool, key_id);
			raw_key->data = p_strdup(_ctx->pool, value.value);
		}
	}

	if (ret == 1) {
		struct mailbox_transaction_context *t =
			mailbox_transaction_begin(box, 0, __func__);
		struct dcrypt_private_key *key;
		const struct raw_key *raw_key;
		const char *algo = ctx->new_password != NULL ?
					MAIL_CRYPT_PW_CIPHER :
					NULL;
		string_t *newkey = t_str_new(256);

		array_foreach(&raw_keys, raw_key) {
			struct mail_attribute_value value;

			if (!dcrypt_key_load_private(&key, raw_key->data,
						    ctx->old_password, NULL,
						    &error)) {
				doveadm_print(t_strdup_printf("dcrypt_key_load_private(%s) failed: %s",
					raw_key->id,
					error));
				_ctx->exit_code = EX_DATAERR;
				ret = -1;
				break;
			}

			/* save it */
			str_truncate(newkey, 0);

			if (!dcrypt_key_store_private(key, DCRYPT_FORMAT_DOVECOT,
						      algo, newkey,
						      ctx->new_password,
						      NULL, &error)) {
				doveadm_print(t_strdup_printf("dcrypt_key_store_private(%s) failed: %s",
					raw_key->id,
					error));
				_ctx->exit_code = EX_DATAERR;
				ret = -1;
			}

			dcrypt_key_unref_private(&key);
			if (ret == -1) break;

			i_zero(&value);
			value.value = str_c(newkey);

			/* and store it */
			if (mailbox_attribute_set(t, MAIL_ATTRIBUTE_TYPE_PRIVATE,
						  raw_key->attr, &value) < 0) {
				doveadm_print(t_strdup_printf("mailbox_attribute_set(%s, %s) failed: %s",
					mailbox_get_vname(box),
					raw_key->attr,
					mailbox_get_last_internal_error(box, NULL)));
				_ctx->exit_code = EX_TEMPFAIL;
				ret = -1;
				break;
			}
			count++;
		}

		if (ret < 1) {
			mailbox_transaction_rollback(&t);
		} else {
			if (mailbox_transaction_commit(&t) < 0) {
				doveadm_print(t_strdup_printf("mailbox_transaction_commit(%s) failed: %s",
					mailbox_get_vname(box),
					mailbox_get_last_internal_error(box, NULL)));
			} else {
				doveadm_print(t_strdup_printf("Changed password for %u key(s)",
							     count));
			}
		}
	}

	(void)mailbox_attribute_iter_deinit(&iter);
	mailbox_free(&box);

	return ret;
}


static bool cmd_mcp_keypair_generate_parse_arg(struct doveadm_mail_cmd_context *_ctx, int c)
{
	struct mcp_cmd_context *ctx =
		(struct mcp_cmd_context *)_ctx;

	switch (c) {
	case 'U':
		ctx->userkey_only = TRUE;
		break;
	case 'R':
		ctx->recrypt_box_keys = TRUE;
		break;
	case 'f':
		ctx->force = TRUE;
		break;
	default:
		return FALSE;
	}
	return TRUE;

}

static bool cmd_mcp_key_password_parse_arg(struct doveadm_mail_cmd_context *_ctx, int c)
{
	struct mcp_cmd_context *ctx =
		(struct mcp_cmd_context *)_ctx;

	switch (c) {
	case 'N':
		ctx->ask_new_password = TRUE;
		break;
	case 'O':
		ctx->ask_old_password = TRUE;
		break;
	case 'C':
		ctx->clear_password = TRUE;
		break;
	case 'o':
		ctx->old_password = p_strdup(_ctx->pool, optarg);
		break;
	case 'n':
		ctx->new_password = p_strdup(_ctx->pool, optarg);
		break;
	default:
		return FALSE;
	}
	return TRUE;
}

static bool cmd_mcp_key_parse_arg(struct doveadm_mail_cmd_context *_ctx, int c)
{
	struct mcp_cmd_context *ctx =
		(struct mcp_cmd_context *)_ctx;

	switch (c) {
	case 'U':
		ctx->userkey_only = TRUE;
		break;
	default:
		return FALSE;
	}
	return TRUE;

}

static struct doveadm_mail_cmd_context *cmd_mcp_keypair_generate_alloc(void)
{
	struct mcp_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct mcp_cmd_context);
	ctx->ctx.getopt_args = "URf";
	ctx->ctx.v.parse_arg = cmd_mcp_keypair_generate_parse_arg;
	ctx->ctx.v.run = cmd_mcp_keypair_generate_run;
	return &ctx->ctx;
}

static struct doveadm_mail_cmd_context *cmd_mcp_key_list_alloc(void)
{
	struct mcp_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct mcp_cmd_context);
	ctx->ctx.getopt_args = "U";
	ctx->ctx.v.parse_arg = cmd_mcp_key_parse_arg;
	ctx->ctx.v.run = cmd_mcp_key_list_run;
	return &ctx->ctx;
}

static struct doveadm_mail_cmd_context *cmd_mcp_key_export_alloc(void)
{
	struct mcp_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct mcp_cmd_context);
	ctx->ctx.getopt_args = "U";
	ctx->ctx.v.parse_arg = cmd_mcp_key_parse_arg;
	ctx->ctx.v.run = cmd_mcp_key_export_run;
	return &ctx->ctx;
}

static struct doveadm_mail_cmd_context *cmd_mcp_key_password_alloc(void)
{
	struct mcp_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct mcp_cmd_context);
	ctx->ctx.getopt_args = "NOCo:n:";
	ctx->ctx.v.parse_arg = cmd_mcp_key_password_parse_arg;
	ctx->ctx.v.run = cmd_mcp_key_password_run;
	return &ctx->ctx;
}

struct doveadm_cmd_ver2 doveadm_cmd_mcp_keypair_generate = {
	.name = "mailbox cryptokey generate",
	.mail_cmd = cmd_mcp_keypair_generate_alloc,
	.usage = DOVEADM_CMD_MAIL_USAGE_PREFIX "[-URf] mailbox [ mailbox .. ]",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('U', "user-key-only", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAM('R', "re-encrypt-box-keys", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAM('f', "force", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAM('\0', "mailbox", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};

struct doveadm_cmd_ver2 doveadm_cmd_mcp_key_list = {
	.name = "mailbox cryptokey list",
	.mail_cmd = cmd_mcp_key_list_alloc,
	.usage = DOVEADM_CMD_MAIL_USAGE_PREFIX "-U | mailbox [ mailbox .. ]",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('U', "user-key", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAM('\0', "mailbox", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};

struct doveadm_cmd_ver2 doveadm_cmd_mcp_key_export = {
	.name = "mailbox cryptokey export",
	.mail_cmd = cmd_mcp_key_export_alloc,
	.usage = DOVEADM_CMD_MAIL_USAGE_PREFIX "-U | mailbox [ mailbox .. ]",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('U', "user-key", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAM('\0', "mailbox", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};

struct doveadm_cmd_ver2 doveadm_cmd_mcp_key_password = {
	.name = "mailbox cryptokey password",
	.mail_cmd = cmd_mcp_key_password_alloc,
	.usage = DOVEADM_CMD_MAIL_USAGE_PREFIX "[-NOC] [-opassword] [-npassword]",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('C', "clear-password", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAM('N', "ask-new-password", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAM('n', "new-password", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('O', "ask-old-password", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('o', "old-password", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAMS_END
};

void doveadm_mail_crypt_plugin_init(struct module *mod ATTR_UNUSED)
{
	doveadm_cmd_register_ver2(&doveadm_cmd_mcp_keypair_generate);
	doveadm_cmd_register_ver2(&doveadm_cmd_mcp_key_list);
	doveadm_cmd_register_ver2(&doveadm_cmd_mcp_key_export);
	doveadm_cmd_register_ver2(&doveadm_cmd_mcp_key_password);
}

void doveadm_mail_crypt_plugin_deinit(void)
{
}
