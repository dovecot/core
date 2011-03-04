/* Copyright (c) 2011 Dovecot authors, see the included COPYING file */

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
	bool get_match_me;
};

const char *doveadm_acl_plugin_version = DOVECOT_VERSION;

void doveadm_acl_plugin_init(struct module *module);
void doveadm_acl_plugin_deinit(void);

static int
cmd_acl_mailbox_open(struct mail_user *user, const char *mailbox,
		     struct mailbox **box_r)
{
	struct acl_user *auser = ACL_USER_CONTEXT(user);
	struct mail_namespace *ns;
	struct mailbox *box;
	const char *storage_name;

	if (auser == NULL) {
		i_error("ACL not enabled for %s", user->username);
		return -1;
	}

	storage_name = mailbox;
	ns = mail_namespace_find(user->namespaces, &storage_name);
	if (ns == NULL) {
		i_error("No namespace found for mailbox %s", mailbox);
		return -1;
	}
	box = mailbox_alloc(ns->list, storage_name,
			    MAILBOX_FLAG_READONLY | MAILBOX_FLAG_KEEP_RECENT |
			    MAILBOX_FLAG_IGNORE_ACLS);
	if (mailbox_open(box) < 0) {
		i_error("Can't open mailbox %s: %s", mailbox,
			mail_storage_get_last_error(box->storage, NULL));
		mailbox_free(&box);
		return -1;
	}
	*box_r = box;
	return 0;
}

static void cmd_acl_get_right(const struct acl_rights *rights)
{
	const char *id = "";
	string_t *str;

	switch (rights->id_type) {
	case ACL_ID_ANYONE:
		id = ACL_ID_NAME_ANYONE;
		break;
	case ACL_ID_AUTHENTICATED:
		id = ACL_ID_NAME_AUTHENTICATED;
		break;
	case ACL_ID_OWNER:
		id = ACL_ID_NAME_OWNER;
		break;
	case ACL_ID_USER:
		id = t_strconcat(ACL_ID_NAME_USER_PREFIX,
				 rights->identifier, NULL);
		break;
	case ACL_ID_GROUP:
		id = t_strconcat(ACL_ID_NAME_GROUP_PREFIX,
				 rights->identifier, NULL);
		break;
	case ACL_ID_GROUP_OVERRIDE:
		id = t_strconcat(ACL_ID_NAME_GROUP_OVERRIDE_PREFIX,
				 rights->identifier, NULL);
		break;
	case ACL_ID_TYPE_COUNT:
		i_unreached();
	}
	doveadm_print(id);

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

static void cmd_acl_get_mailbox(struct doveadm_acl_cmd_context *ctx,
				struct mailbox *box)
{
	struct acl_object *aclobj = acl_mailbox_get_aclobj(box);
	struct acl_backend *backend;
	struct acl_object_list_iter *iter;
	struct acl_rights rights;
	int ret;

	backend = acl_mailbox_list_get_backend(box->list);

	iter = acl_object_list_init(aclobj);
	while ((ret = acl_object_list_next(iter, &rights)) > 0) T_BEGIN {
		if (!ctx->get_match_me ||
		    acl_backend_rights_match_me(backend, &rights))
			cmd_acl_get_right(&rights);
	} T_END;
	acl_object_list_deinit(&iter);

	if (ret < 0)
		i_error("ACL iteration failed");
}

static void
cmd_acl_get_run(struct doveadm_mail_cmd_context *_ctx,
		struct mail_user *user)
{
	struct doveadm_acl_cmd_context *ctx =
		(struct doveadm_acl_cmd_context *)_ctx;
	const char *mailbox = _ctx->args[0];
	struct mailbox *box;

	if (cmd_acl_mailbox_open(user, mailbox, &box) < 0)
		return;

	cmd_acl_get_mailbox(ctx, box);
	mailbox_free(&box);
}

static bool cmd_acl_get_parse_arg(struct doveadm_mail_cmd_context *_ctx, int c)
{
	struct doveadm_acl_cmd_context *ctx =
		(struct doveadm_acl_cmd_context *)_ctx;

	switch (c) {
	case 'm':
		ctx->get_match_me = TRUE;
		break;
	default:
		return FALSE;
	}
	return TRUE;
}

static void cmd_acl_get_init(struct doveadm_mail_cmd_context *ctx ATTR_UNUSED,
			     const char *const args[])
{
	if (args[0] == NULL)
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
	ctx->ctx.getopt_args = "m";
	ctx->ctx.v.parse_arg = cmd_acl_get_parse_arg;
	ctx->ctx.v.run = cmd_acl_get_run;
	ctx->ctx.v.init = cmd_acl_get_init;
	doveadm_print_init(DOVEADM_PRINT_TYPE_TABLE);
	return &ctx->ctx;
}

static void
cmd_acl_rights_run(struct doveadm_mail_cmd_context *ctx, struct mail_user *user)
{
	const char *mailbox = ctx->args[0];
	struct mailbox *box;
	struct acl_object *aclobj;
	const char *const *rights;

	if (cmd_acl_mailbox_open(user, mailbox, &box) < 0)
		return;

	aclobj = acl_mailbox_get_aclobj(box);
	if (acl_object_get_my_rights(aclobj, pool_datastack_create(),
				     &rights) < 0)
		i_error("Failed to get rights");
	else
		doveadm_print(t_strarray_join(rights, " "));
	mailbox_free(&box);
}

static void cmd_acl_rights_init(struct doveadm_mail_cmd_context *ctx ATTR_UNUSED,
				const char *const args[])
{
	if (args[0] == NULL)
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

static bool is_standard_right(const char *name)
{
	unsigned int i;

	for (i = 0; all_mailbox_rights[i] != NULL; i++) {
		if (strcmp(all_mailbox_rights[i], name) == 0)
			return TRUE;
	}
	return FALSE;
}

static void
cmd_acl_set_run(struct doveadm_mail_cmd_context *ctx, struct mail_user *user)
{
	const char *mailbox = ctx->args[0], *id = ctx->args[1];
	const char *const *rights = ctx->args + 2;
	ARRAY_TYPE(const_string) dest_rights, dest_neg_rights, *dest;
	struct mailbox *box;
	struct acl_object *aclobj;
	struct acl_rights_update update;
	unsigned int i, j;

	if (cmd_acl_mailbox_open(user, mailbox, &box) < 0)
		return;

	memset(&update, 0, sizeof(update));
	update.modify_mode = ACL_MODIFY_MODE_REPLACE;
	update.neg_modify_mode = ACL_MODIFY_MODE_REPLACE;

	if (acl_identifier_parse(id, &update.rights) < 0)
		i_fatal("Invalid ID: %s", id);

	t_array_init(&dest_rights, 8);
	t_array_init(&dest_neg_rights, 8);
	for (i = 0; rights[i] != NULL; i++) {
		const char *right = rights[i];

		if (right[0] != '-')
			dest = &dest_rights;
		else {
			right++;
			dest = &dest_neg_rights;
		}
		if (strcmp(right, "all") != 0) {
			if (*right == ':') {
				/* non-standard right */
				right++;
				array_append(dest, &right, 1);
			} else if (is_standard_right(right)) {
				array_append(dest, &right, 1);
			} else {
				i_fatal("Invalid right '%s'", right);
			}
		} else {
			for (j = 0; all_mailbox_rights[j] != NULL; j++)
				array_append(dest, &all_mailbox_rights[j], 1);
		}
	}
	if (array_count(&dest_rights) > 0) {
		(void)array_append_space(&dest_rights);
		update.rights.rights = array_idx(&dest_rights, 0);
	}
	if (array_count(&dest_neg_rights) > 0) {
		(void)array_append_space(&dest_neg_rights);
		update.rights.neg_rights = array_idx(&dest_neg_rights, 0);
	}

	aclobj = acl_mailbox_get_aclobj(box);
	if (acl_object_update(aclobj, &update) < 0)
		i_error("Failed to set ACL");
	mailbox_free(&box);
}

static void cmd_acl_set_init(struct doveadm_mail_cmd_context *ctx ATTR_UNUSED,
			     const char *const args[])
{
	if (str_array_length(args) < 3)
		doveadm_mail_help_name("acl set");
}

static struct doveadm_mail_cmd_context *
cmd_acl_set_alloc(void)
{
	struct doveadm_mail_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct doveadm_mail_cmd_context);
	ctx->v.run = cmd_acl_set_run;
	ctx->v.init = cmd_acl_set_init;
	return ctx;
}

static void
cmd_acl_delete_run(struct doveadm_mail_cmd_context *ctx, struct mail_user *user)
{
	const char *mailbox = ctx->args[0], *id = ctx->args[1];
	struct mailbox *box;
	struct acl_object *aclobj;
	struct acl_rights_update update;

	if (cmd_acl_mailbox_open(user, mailbox, &box) < 0)
		return;

	memset(&update, 0, sizeof(update));
	update.modify_mode = ACL_MODIFY_MODE_CLEAR;
	update.neg_modify_mode = ACL_MODIFY_MODE_CLEAR;

	if (acl_identifier_parse(id, &update.rights) < 0)
		i_fatal("Invalid ID: %s", id);

	aclobj = acl_mailbox_get_aclobj(box);
	if (acl_object_update(aclobj, &update) < 0)
		i_error("Failed to set ACL");
	mailbox_free(&box);
}

static void cmd_acl_delete_init(struct doveadm_mail_cmd_context *ctx ATTR_UNUSED,
				const char *const args[])
{
	if (str_array_length(args) < 2)
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

static bool cmd_acl_debug_mailbox(struct mailbox *box, bool *retry_r)
{
	struct mail_namespace *ns = mailbox_get_namespace(box);
	struct acl_user *auser = ACL_USER_CONTEXT(ns->user);
	struct acl_object *aclobj = acl_mailbox_get_aclobj(box);
	struct acl_backend *backend = acl_mailbox_list_get_backend(box->list);
	struct acl_mailbox_list_context *iter;
	struct acl_lookup_dict_iter *diter;
	const char *const *rights, *name;
	string_t *str;
	int ret;
	bool all_ok = TRUE;

	*retry_r = FALSE;

	if (box->private_flags_mask == 0)
		i_info("All message flags are shared across users in mailbox");
	else {
		str = t_str_new(64);
		imap_write_flags(str, box->private_flags_mask, NULL);
		i_info("Per-user private flags in mailbox: %s", str_c(str));
	}

	/* check if user has lookup right */
	if (acl_object_get_my_rights(aclobj, pool_datastack_create(),
				     &rights) < 0)
		i_fatal("Failed to get rights");

	if (rights == NULL || rights[0] == NULL)
		i_info("User %s has no rights for mailbox", ns->user->username);
	else {
		i_info("User %s has rights: %s",
		       ns->user->username, t_strarray_join(rights, " "));
	}
	if (!str_array_find(rights, MAIL_ACL_LOOKUP)) {
		i_error("User %s is missing 'lookup' right",
			ns->user->username);
		return FALSE;
	}

	/* check if mailbox is listable */
	if (ns->type == NAMESPACE_PRIVATE) {
		i_info("Mailbox in user's private namespace");
		return TRUE;
	}

	iter = acl_backend_nonowner_lookups_iter_init(backend);
	while ((ret = acl_backend_nonowner_lookups_iter_next(iter, &name)) > 0) {
		if (strcmp(name, box->name) == 0)
			break;
	}
	acl_backend_nonowner_lookups_iter_deinit(&iter);
	if (ret < 0)
		i_fatal("ACL non-owner iteration failed");
	if (ret == 0) {
		i_error("Mailbox not found from dovecot-acl-list, rebuilding");
		if (acl_backend_nonowner_lookups_rebuild(backend) < 0)
			i_fatal("dovecot-acl-list rebuilding failed");
		all_ok = FALSE;
		*retry_r = TRUE;
	} else {
		i_info("Mailbox found from dovecot-acl-list");
	}

	if (ns->type == NAMESPACE_PUBLIC) {
		i_info("Mailbox is in public namespace");
		return TRUE;
	}

	if (!acl_lookup_dict_is_enabled(auser->acl_lookup_dict)) {
		i_error("acl_lookup_dict not enabled");
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
		i_error("User %s not found from ACL shared dict, rebuilding",
			ns->owner->username);
		if (acl_lookup_dict_rebuild(auser->acl_lookup_dict) < 0)
			i_fatal("ACL lookup dict rebuild failed");
		all_ok = FALSE;
		*retry_r = TRUE;
	} else {
		i_info("User %s found from ACL shared dict",
		       ns->owner->username);
	}
	return all_ok;
}

static void
cmd_acl_debug_run(struct doveadm_mail_cmd_context *ctx, struct mail_user *user)
{
	const char *mailbox = ctx->args[0];
	struct mailbox *box;
	bool ret, retry;

	if (cmd_acl_mailbox_open(user, mailbox, &box) < 0)
		return;

	ret = cmd_acl_debug_mailbox(box, &retry);
	if (!ret && retry) {
		i_info("Retrying after rebuilds:");
		ret = cmd_acl_debug_mailbox(box, &retry);
	}
	if (ret)
		i_info("Mailbox %s is visible in LIST", box->vname);
	else
		i_info("Mailbox %s is NOT visible in LIST", box->vname);
	mailbox_free(&box);
}

static void cmd_acl_debug_init(struct doveadm_mail_cmd_context *ctx ATTR_UNUSED,
			       const char *const args[])
{
	if (args[0] == NULL)
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

static struct doveadm_mail_cmd acl_commands[] = {
	{ cmd_acl_get_alloc, "acl get", "[-m] <mailbox>" },
	{ cmd_acl_rights_alloc, "acl rights", "<mailbox>" },
	{ cmd_acl_set_alloc, "acl set", "<mailbox> <id> <rights>" },
	{ cmd_acl_delete_alloc, "acl delete", "<mailbox> <id>" },
	{ cmd_acl_debug_alloc, "acl debug", "<mailbox>" }
};

void doveadm_acl_plugin_init(struct module *module ATTR_UNUSED)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(acl_commands); i++)
		doveadm_mail_register_cmd(&acl_commands[i]);
}

void doveadm_acl_plugin_deinit(void)
{
}
