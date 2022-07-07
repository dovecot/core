/* Copyright (c) 2011-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "module-dir.h"
#include "imap-util.h"
#include "acl-plugin.h"
#include "acl-api-private.h"
#include "acl-lookup-dict.h"
#include "doveadm-print.h"
#include "doveadm-mail.h"

struct doveadm_acl_cmd_context {
	struct doveadm_mail_cmd_context ctx;
	const char *mailbox;
	const char *id;
	const char *const *rights;
	enum acl_modify_mode modify_mode;
	bool get_match_me:1;
};

const char *doveadm_acl_plugin_version = DOVECOT_ABI_VERSION;

void doveadm_acl_plugin_init(struct module *module);
void doveadm_acl_plugin_deinit(void);

static int
cmd_acl_mailbox_open(struct doveadm_mail_cmd_context *ctx,
		     struct mail_user *user, const char *mailbox,
		     struct mailbox **box_r)
{
	struct acl_user *auser = ACL_USER_CONTEXT(user);
	struct mail_namespace *ns;
	struct mailbox *box;

	if (auser == NULL) {
		e_error(user->event, "ACL not enabled for %s", user->username);
		doveadm_mail_failed_error(ctx, MAIL_ERROR_NOTFOUND);
		return -1;
	}

	ns = mail_namespace_find(user->namespaces, mailbox);
	box = mailbox_alloc(ns->list, mailbox,
			    MAILBOX_FLAG_READONLY | MAILBOX_FLAG_IGNORE_ACLS);
	if (mailbox_open(box) < 0) {
		e_error(box->event, "Can't open mailbox: %s",
			mailbox_get_last_internal_error(box, NULL));
		doveadm_mail_failed_mailbox(ctx, box);
		mailbox_free(&box);
		return -1;
	}
	*box_r = box;
	return 0;
}

static void cmd_acl_get_right(const struct acl_rights *rights)
{
	string_t *str;

	doveadm_print(acl_rights_get_id(rights));

	if (rights->global)
		doveadm_print("global");
	else
		doveadm_print("");

	str = t_str_new(256);
	if (rights->rights != NULL)
		str_append(str, t_strarray_join(rights->rights, " "));
	if (rights->neg_rights != NULL) {
		if (str_len(str) > 0)
			str_append_c(str, ' ');
		str_append_c(str, '-');
		str_append(str, t_strarray_join(rights->neg_rights, " -"));
	}
	doveadm_print(str_c(str));
}

static int cmd_acl_get_mailbox(struct doveadm_acl_cmd_context *ctx,
			       struct mailbox *box)
{
	struct acl_object *aclobj = acl_mailbox_get_aclobj(box);
	struct acl_backend *backend;
	struct acl_object_list_iter *iter;
	struct acl_rights rights;
	int ret;

	backend = acl_mailbox_list_get_backend(box->list);

	iter = acl_object_list_init(aclobj);
	while (acl_object_list_next(iter, &rights)) T_BEGIN {
		if (!ctx->get_match_me ||
		    acl_backend_rights_match_me(backend, &rights))
			cmd_acl_get_right(&rights);
	} T_END;

	if ((ret = acl_object_list_deinit(&iter))<0) {
		e_error(box->event, "ACL iteration failed");
		doveadm_mail_failed_error(&ctx->ctx, MAIL_ERROR_TEMP);
	}
	return ret;
}

static int
cmd_acl_get_run(struct doveadm_mail_cmd_context *_ctx,
		struct mail_user *user)
{
	struct doveadm_acl_cmd_context *ctx =
		container_of(_ctx, struct doveadm_acl_cmd_context, ctx);
	struct mailbox *box;
	int ret;

	if (cmd_acl_mailbox_open(_ctx, user, ctx->mailbox, &box) < 0)
		return -1;

	ret = cmd_acl_get_mailbox(ctx, box);
	mailbox_free(&box);
	return ret;
}

static void cmd_acl_get_init(struct doveadm_mail_cmd_context *_ctx)
{
	struct doveadm_acl_cmd_context *ctx =
		container_of(_ctx, struct doveadm_acl_cmd_context, ctx);
	struct doveadm_cmd_context *cctx = _ctx->cctx;

	ctx->get_match_me = doveadm_cmd_param_flag(cctx, "match-me");
	if (!doveadm_cmd_param_str(cctx, "mailbox", &ctx->mailbox))
		doveadm_mail_help_name("acl get");
	doveadm_print_header("id", "ID", 0);
	doveadm_print_header("global", "Global", 0);
	doveadm_print_header("rights", "Rights", 0);
}

static struct doveadm_mail_cmd_context *
cmd_acl_get_alloc(void)
{
	struct doveadm_acl_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct doveadm_acl_cmd_context);
	ctx->ctx.v.run = cmd_acl_get_run;
	ctx->ctx.v.init = cmd_acl_get_init;
	doveadm_print_init(DOVEADM_PRINT_TYPE_TABLE);
	return &ctx->ctx;
}

static int
cmd_acl_rights_run(struct doveadm_mail_cmd_context *_ctx, struct mail_user *user)
{
	struct doveadm_acl_cmd_context *ctx =
		container_of(_ctx, struct doveadm_acl_cmd_context, ctx);

	struct mailbox *box;
	struct acl_object *aclobj;
	const char *const *rights;
	int ret = 0;

	if (cmd_acl_mailbox_open(_ctx, user, ctx->mailbox, &box) < 0)
		return -1;

	aclobj = acl_mailbox_get_aclobj(box);
	if (acl_object_get_my_rights(aclobj, pool_datastack_create(),
				     &rights) < 0) {
		doveadm_mail_failed_error(_ctx, MAIL_ERROR_TEMP);
		e_error(box->event, "Failed to get rights");
		ret = -1;
	} else {
		doveadm_print(t_strarray_join(rights, " "));
	}
	mailbox_free(&box);
	return ret;
}

static void cmd_acl_rights_init(struct doveadm_mail_cmd_context *_ctx)
{
	struct doveadm_cmd_context *cctx = _ctx->cctx;
	struct doveadm_acl_cmd_context *ctx =
		container_of(_ctx, struct doveadm_acl_cmd_context, ctx);

	if (!doveadm_cmd_param_str(cctx, "mailbox", &ctx->mailbox))
		doveadm_mail_help_name("acl rights");

	doveadm_print_header("rights", "Rights", 0);
}

static struct doveadm_mail_cmd_context *
cmd_acl_rights_alloc(void)
{
	struct doveadm_mail_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct doveadm_mail_cmd_context);
	ctx->v.run = cmd_acl_rights_run;
	ctx->v.init = cmd_acl_rights_init;
	doveadm_print_init(DOVEADM_PRINT_TYPE_TABLE);
	return ctx;
}

static int
cmd_acl_mailbox_update(struct doveadm_mail_cmd_context *ctx, struct mailbox *box,
		       const struct acl_rights_update *update)
{
	struct mailbox_transaction_context *t;
	int ret;

	t = mailbox_transaction_begin(box, MAILBOX_TRANSACTION_FLAG_EXTERNAL |
				      ctx->transaction_flags, __func__);
	ret = acl_mailbox_update_acl(t, update);
	if (mailbox_transaction_commit(&t) < 0)
		ret = -1;
	return ret;
}

static int
cmd_acl_set_run(struct doveadm_mail_cmd_context *_ctx, struct mail_user *user)
{
	struct doveadm_acl_cmd_context *ctx =
		container_of(_ctx, struct doveadm_acl_cmd_context, ctx);

	struct mailbox *box;
	struct acl_rights_update update;
	const char *error;
	int ret;

	if (cmd_acl_mailbox_open(_ctx, user, ctx->mailbox, &box) < 0)
		return -1;

	i_zero(&update);
	update.modify_mode = ctx->modify_mode;
	update.neg_modify_mode = ctx->modify_mode;
	if (acl_rights_update_import(&update, ctx->id, ctx->rights, &error) < 0)
		i_fatal_status(EX_USAGE, "%s", error);
	if ((ret = cmd_acl_mailbox_update(&ctx->ctx, box, &update)) < 0) {
		e_error(box->event, "Failed to set ACL: %s",
			mailbox_get_last_internal_error(box, NULL));
		doveadm_mail_failed_error(_ctx, MAIL_ERROR_TEMP);
	}
	mailbox_free(&box);
	return ret;
}

static void cmd_acl_set_init(struct doveadm_mail_cmd_context *_ctx)
{
	struct doveadm_cmd_context *cctx = _ctx->cctx;
	struct doveadm_acl_cmd_context *ctx =
		container_of(_ctx, struct doveadm_acl_cmd_context, ctx);

	if (!doveadm_cmd_param_str(cctx, "mailbox", &ctx->mailbox) ||
	    !doveadm_cmd_param_str(cctx, "id", &ctx->id) ||
	    !doveadm_cmd_param_array(cctx, "right", &ctx->rights))
		doveadm_mail_help_name("acl set");
}

static struct doveadm_mail_cmd_context *
cmd_acl_change_alloc(enum acl_modify_mode modify_mode)
{
	struct doveadm_acl_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct doveadm_acl_cmd_context);
	ctx->ctx.v.run = cmd_acl_set_run;
	ctx->ctx.v.init = cmd_acl_set_init;
	ctx->modify_mode = modify_mode;
	return &ctx->ctx;
}

static struct doveadm_mail_cmd_context *cmd_acl_set_alloc(void)
{
	return cmd_acl_change_alloc(ACL_MODIFY_MODE_REPLACE);
}

static struct doveadm_mail_cmd_context *cmd_acl_add_alloc(void)
{
	return cmd_acl_change_alloc(ACL_MODIFY_MODE_ADD);
}

static struct doveadm_mail_cmd_context *cmd_acl_remove_alloc(void)
{
	return cmd_acl_change_alloc(ACL_MODIFY_MODE_REMOVE);
}

static int
cmd_acl_delete_run(struct doveadm_mail_cmd_context *_ctx, struct mail_user *user)
{
	struct doveadm_acl_cmd_context *ctx =
		container_of(_ctx, struct doveadm_acl_cmd_context, ctx);

	struct mailbox *box;
	struct acl_rights_update update;
	const char *error;
	int ret = 0;

	if (cmd_acl_mailbox_open(_ctx, user, ctx->mailbox, &box) < 0)
		return -1;

	i_zero(&update);
	if (acl_rights_update_import(&update, ctx->id, NULL, &error) < 0)
		i_fatal_status(EX_USAGE, "%s", error);
	if ((ret = cmd_acl_mailbox_update(_ctx, box, &update)) < 0) {
		e_error(box->event, "Failed to delete ACL: %s",
			mailbox_get_last_internal_error(box, NULL));
		doveadm_mail_failed_error(_ctx, MAIL_ERROR_TEMP);
	}
	mailbox_free(&box);
	return ret;
}

static void cmd_acl_delete_init(struct doveadm_mail_cmd_context *_ctx)
{
	struct doveadm_cmd_context *cctx = _ctx->cctx;
	struct doveadm_acl_cmd_context *ctx =
		container_of(_ctx, struct doveadm_acl_cmd_context, ctx);

	if (!doveadm_cmd_param_str(cctx, "mailbox", &ctx->mailbox) ||
	    !doveadm_cmd_param_str(cctx, "id", &ctx->id))
		doveadm_mail_help_name("acl delete");
}

static struct doveadm_mail_cmd_context *
cmd_acl_delete_alloc(void)
{
	struct doveadm_mail_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct doveadm_mail_cmd_context);
	ctx->v.run = cmd_acl_delete_run;
	ctx->v.init = cmd_acl_delete_init;
	return ctx;
}

static int
cmd_acl_recalc_run(struct doveadm_mail_cmd_context *ctx, struct mail_user *user)
{
	struct acl_user *auser = ACL_USER_CONTEXT(user);

	if (auser == NULL) {
		e_error(user->event, "ACL not enabled for %s", user->username);
		doveadm_mail_failed_error(ctx, MAIL_ERROR_NOTFOUND);
		return -1;
	}
	if (acl_lookup_dict_rebuild(auser->acl_lookup_dict) < 0) {
		e_error(user->event, "Failed to recalculate ACL dicts");
		doveadm_mail_failed_error(ctx, MAIL_ERROR_TEMP);
		return -1;
	}
	return 0;
}

static struct doveadm_mail_cmd_context *
cmd_acl_recalc_alloc(void)
{
	struct doveadm_mail_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct doveadm_mail_cmd_context);
	ctx->v.run = cmd_acl_recalc_run;
	return ctx;
}

static int
cmd_acl_debug_mailbox_open(struct doveadm_mail_cmd_context *ctx,
			   struct mail_user *user, const char *mailbox,
			   struct mailbox **box_r)
{
	struct acl_user *auser = ACL_USER_CONTEXT_REQUIRE(user);
	struct mail_namespace *ns;
	struct mailbox *box;
	const char *path, *errstr;
	enum mail_error error;

	ns = mail_namespace_find(user->namespaces, mailbox);
	box = mailbox_alloc(ns->list, mailbox,
			    MAILBOX_FLAG_READONLY | MAILBOX_FLAG_IGNORE_ACLS);
	if (mailbox_open(box) < 0) {
		errstr = mail_storage_get_last_internal_error(box->storage, &error);
		errstr = t_strdup(errstr);
		doveadm_mail_failed_error(ctx, error);

		if (error != MAIL_ERROR_NOTFOUND ||
		    mailbox_get_path_to(box, MAILBOX_LIST_PATH_TYPE_MAILBOX,
					&path) <= 0)
			e_error(box->event,
				"Can't open mailbox %s: %s", mailbox, errstr);
		else {
			e_error(box->event,
				"Mailbox '%s' in namespace '%s' doesn't exist in %s",
				box->name, ns->prefix, path);
		}
		mailbox_free(&box);
		return -1;
	}

	if (auser == NULL) {
		e_info(box->event,
		       "ACL not enabled for user %s, mailbox can be accessed",
		       user->username);
		doveadm_mail_failed_error(ctx, MAIL_ERROR_NOTFOUND);
		mailbox_free(&box);
		return -1;
	}

	*box_r = box;
	return 0;
}

static bool cmd_acl_debug_mailbox(struct mailbox *box, bool *retry_r)
{
	struct mail_namespace *ns = mailbox_get_namespace(box);
	struct acl_user *auser = ACL_USER_CONTEXT_REQUIRE(ns->user);
	struct acl_object *aclobj = acl_mailbox_get_aclobj(box);
	struct acl_backend *backend = acl_mailbox_list_get_backend(box->list);
	struct acl_mailbox_list_context *iter;
	struct acl_lookup_dict_iter *diter;
	const char *const *rights, *name, *path;
	enum mail_flags private_flags_mask;
	string_t *str;
	int ret;
	bool all_ok = TRUE;

	*retry_r = FALSE;

	e_info(box->event, "Mailbox '%s' is in namespace '%s'",
	       box->name, box->list->ns->prefix);
	if (mailbox_get_path_to(box, MAILBOX_LIST_PATH_TYPE_MAILBOX, &path) > 0)
		e_info(box->event, "Mailbox path: %s", path);

	private_flags_mask = mailbox_get_private_flags_mask(box);
	if (private_flags_mask == 0)
		e_info(box->event, "All message flags are shared across users in mailbox");
	else {
		str = t_str_new(64);
		imap_write_flags(str, private_flags_mask, NULL);
		e_info(box->event, "Per-user private flags in mailbox: %s", str_c(str));
	}

	/* check if user has lookup right */
	if (acl_object_get_my_rights(aclobj, pool_datastack_create(),
				     &rights) < 0)
		i_fatal("Failed to get rights");

	if (rights[0] == NULL)
		e_info(box->event, "User %s has no rights for mailbox", ns->user->username);
	else {
		e_info(box->event, "User %s has rights: %s",
		       ns->user->username, t_strarray_join(rights, " "));
	}
	if (!str_array_find(rights, MAIL_ACL_LOOKUP)) {
		e_error(box->event, "User %s is missing 'lookup' right",
			ns->user->username);
		return FALSE;
	}

	/* check if mailbox is listable */
	if (ns->type == MAIL_NAMESPACE_TYPE_PRIVATE) {
		e_info(box->event, "Mailbox in user's private namespace");
		return TRUE;
	}

	iter = acl_backend_nonowner_lookups_iter_init(backend);
	while (acl_backend_nonowner_lookups_iter_next(iter, &name)) {
		if (strcmp(name, box->name) == 0)
			break;
	}
	if ((ret = acl_backend_nonowner_lookups_iter_deinit(&iter))<0)
		i_fatal("ACL non-owner iteration failed");
	if (ret == 0) {
		e_error(box->event, "Mailbox not found from dovecot-acl-list, rebuilding");
		if (acl_backend_nonowner_lookups_rebuild(backend) < 0)
			i_fatal("dovecot-acl-list rebuilding failed");
		all_ok = FALSE;
		*retry_r = TRUE;
	} else {
		e_info(box->event, "Mailbox found from dovecot-acl-list");
	}

	if (ns->type == MAIL_NAMESPACE_TYPE_PUBLIC) {
		e_info(box->event, "Mailbox is in public namespace");
		return TRUE;
	}

	if (!acl_lookup_dict_is_enabled(auser->acl_lookup_dict)) {
		e_error(box->event, "acl_lookup_dict not enabled");
		return FALSE;
	}

	/* shared namespace. see if it's in acl lookup dict */
	diter = acl_lookup_dict_iterate_visible_init(auser->acl_lookup_dict);
	while ((name = acl_lookup_dict_iterate_visible_next(diter)) != NULL) {
		if (strcmp(name, ns->owner->username) == 0)
			break;
	}
	if (acl_lookup_dict_iterate_visible_deinit(&diter) < 0)
		i_fatal("ACL shared dict iteration failed");
	if (name == NULL) {
		e_error(box->event, "User %s not found from ACL shared dict, rebuilding",
			ns->owner->username);
		if (acl_lookup_dict_rebuild(auser->acl_lookup_dict) < 0)
			i_fatal("ACL lookup dict rebuild failed");
		all_ok = FALSE;
		*retry_r = TRUE;
	} else {
		e_info(box->event, "User %s found from ACL shared dict",
		       ns->owner->username);
	}
	return all_ok;
}

static int
cmd_acl_debug_run(struct doveadm_mail_cmd_context *_ctx, struct mail_user *user)
{
	struct doveadm_acl_cmd_context *ctx =
		container_of(_ctx, struct doveadm_acl_cmd_context, ctx);

	struct mailbox *box;
	bool ret, retry;

	if (cmd_acl_debug_mailbox_open(_ctx, user, ctx->mailbox, &box) < 0)
		return -1;

	ret = cmd_acl_debug_mailbox(box, &retry);
	if (!ret && retry) {
		e_info(box->event, "Retrying after rebuilds:");
		ret = cmd_acl_debug_mailbox(box, &retry);
	}
	if (ret)
		e_info(box->event, "Mailbox %s is visible in LIST", box->vname);
	else
		e_info(box->event, "Mailbox %s is NOT visible in LIST", box->vname);
	mailbox_free(&box);
	return 0;
}

static void cmd_acl_debug_init(struct doveadm_mail_cmd_context *_ctx)
{
	struct doveadm_cmd_context *cctx = _ctx->cctx;
	struct doveadm_acl_cmd_context *ctx =
		container_of(_ctx, struct doveadm_acl_cmd_context, ctx);

	if (!doveadm_cmd_param_str(cctx, "mailbox", &ctx->mailbox))
		doveadm_mail_help_name("acl debug");
}

static struct doveadm_mail_cmd_context *
cmd_acl_debug_alloc(void)
{
	struct doveadm_mail_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct doveadm_mail_cmd_context);
	ctx->v.run = cmd_acl_debug_run;
	ctx->v.init = cmd_acl_debug_init;
	return ctx;
}

static struct doveadm_cmd_ver2 acl_commands[] = {
{
	.name = "acl get",
	.mail_cmd = cmd_acl_get_alloc,
	.usage = DOVEADM_CMD_MAIL_USAGE_PREFIX "[-m] <mailbox>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('m', "match-me", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAM('\0', "mailbox", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
},
{
	.name = "acl rights",
	.mail_cmd = cmd_acl_rights_alloc,
	.usage = DOVEADM_CMD_MAIL_USAGE_PREFIX "<mailbox>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('\0', "mailbox", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
},
{
	.name = "acl set",
	.mail_cmd = cmd_acl_set_alloc,
	.usage = DOVEADM_CMD_MAIL_USAGE_PREFIX "<mailbox> <id> <right> [<right> ...]",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('\0', "mailbox", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "id", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "right", CMD_PARAM_ARRAY, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
},
{
	.name = "acl add",
	.mail_cmd = cmd_acl_add_alloc,
	.usage = DOVEADM_CMD_MAIL_USAGE_PREFIX "<mailbox> <id> <right> [<right> ...]",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('\0', "mailbox", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "id", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "right", CMD_PARAM_ARRAY, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
},
{
	.name = "acl remove",
	.mail_cmd = cmd_acl_remove_alloc,
	.usage = DOVEADM_CMD_MAIL_USAGE_PREFIX "<mailbox> <id> <right> [<right> ...]",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('\0', "mailbox", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "id", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "right", CMD_PARAM_ARRAY, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
},
{
	.name = "acl delete",
	.mail_cmd = cmd_acl_delete_alloc,
	.usage = DOVEADM_CMD_MAIL_USAGE_PREFIX "<mailbox> <id>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('\0', "mailbox", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "id", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
},
{
	.name = "acl recalc",
	.mail_cmd = cmd_acl_recalc_alloc,
	.usage = DOVEADM_CMD_MAIL_USAGE_PREFIX,
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAMS_END
},
{
	.name = "acl debug",
	.mail_cmd = cmd_acl_debug_alloc,
	.usage = DOVEADM_CMD_MAIL_USAGE_PREFIX "<mailbox>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('\0', "mailbox", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
}
};

void doveadm_acl_plugin_init(struct module *module ATTR_UNUSED)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(acl_commands); i++)
		doveadm_cmd_register_ver2(&acl_commands[i]);
}

void doveadm_acl_plugin_deinit(void)
{
}
