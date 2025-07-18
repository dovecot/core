/* Copyright (c) 2011-2018 Dovecot authors, see the included COPYING file */

/*
   There are various different mailbox names here. Here's an example assuming
    - imapc_list_prefix = "prefix"
    - remote imapc server separator = '/'
    - mailbox_list separator = '^' (actually this is currently always the same
      as remote separator, but this clarifies the example)
    - namespace separator = ':'
    - fs_list separator = '.'
    - mailbox_list storage_name_escape_char = '+'
    - mailbox_list mailbox_list_visible_escape_char = '~'
    - fs_list storage_name_escape_char = '%'

   remote_name = "prefix/~foo/bar^baz+_%_."
   storage_name = "prefix^~foo^bar+5ebaz+2b_%_."
    - separator is changed from / to ^
    - conflicting ^ separator in remote_name is escaped as +5e
    - storage_name_escape character + is escaped as +2b
   vname = "~7efoo:bar.baz+_%_."
    - imapc_list_prefix is dropped
    - mailbox_list_visible_escape_char ~ is escaped into ~7e
    - separator is changed from ^ to :
    - storage_name_escape_characters are unescaped
   fs_name = "prefix.~foo.bar^baz+_%25_%2e"
    - this is generated from remote_name
    - separator is changed from / to .
    - storage_name_escape_character=% and fs_list separator . are escaped
*/

#include "lib.h"
#include "ioloop.h"
#include "str.h"
#include "settings.h"
#include "settings-parser.h"
#include "imap-arg.h"
#include "imap-match.h"
#include "imap-utf7.h"
#include "mail-storage-service.h"
#include "mailbox-tree.h"
#include "mailbox-list-subscriptions.h"
#include "imapc-connection.h"
#include "imapc-storage.h"
#include "imapc-list.h"

struct imapc_mailbox_list_iterate_context {
	struct mailbox_list_iterate_context ctx;
	struct mailbox_tree_context *tree;
	struct mailbox_node *ns_root;

	struct mailbox_tree_iterate_context *iter;
	struct mailbox_info info;
	string_t *special_use;
};

static struct {
	const char *str;
	enum mailbox_info_flags flag;
} imap_list_flags[] = {
	{ "\\NoSelect", MAILBOX_NOSELECT },
	{ "\\NonExistent", MAILBOX_NONEXISTENT },
	{ "\\NoInferiors", MAILBOX_NOINFERIORS },
	{ "\\Subscribed", MAILBOX_SUBSCRIBED },
	{ "\\All", MAILBOX_SPECIALUSE_ALL },
	{ "\\Archive", MAILBOX_SPECIALUSE_ARCHIVE },
	{ "\\Drafts", MAILBOX_SPECIALUSE_DRAFTS },
	{ "\\Flagged", MAILBOX_SPECIALUSE_FLAGGED },
	{ "\\Junk", MAILBOX_SPECIALUSE_JUNK },
	{ "\\Sent", MAILBOX_SPECIALUSE_SENT },
	{ "\\Trash", MAILBOX_SPECIALUSE_TRASH },
	{ "\\Important", MAILBOX_SPECIALUSE_IMPORTANT }
};

extern struct mailbox_list imapc_mailbox_list;

static void imapc_list_send_hierarchy_sep_lookup(struct imapc_mailbox_list *list);
static void imapc_untagged_list(const struct imapc_untagged_reply *reply,
				struct imapc_storage_client *client);
static void imapc_untagged_lsub(const struct imapc_untagged_reply *reply,
				struct imapc_storage_client *client);

static struct mailbox_list *imapc_list_alloc(void)
{
	struct imapc_mailbox_list *list;
	pool_t pool;

	pool = pool_alloconly_create("imapc mailbox list", 1024);
	list = p_new(pool, struct imapc_mailbox_list, 1);
	list->list = imapc_mailbox_list;
	list->list.pool = pool;
	/* separator is set lazily */
	list->mailboxes = mailbox_tree_init('\0');
	mailbox_tree_set_parents_nonexistent(list->mailboxes);
	return &list->list;
}

static int imapc_list_init(struct mailbox_list *_list, const char **error_r)
{
	struct imapc_mailbox_list *list = (struct imapc_mailbox_list *)_list;

	if (imapc_storage_client_create(_list,
					&list->client, error_r) < 0)
		return -1;
	list->client->_list = list;
	list->set = list->client->set;

	if ((_list->ns->flags & NAMESPACE_FLAG_UNUSABLE) != 0) {
		/* Avoid connecting to imapc just to access mailbox names.
		   There are no mailboxes, so the separator doesn't matter. */
		list->root_sep = '/';
	}

	imapc_storage_client_register_untagged(list->client, "LIST",
					       imapc_untagged_list);
	imapc_storage_client_register_untagged(list->client, "LSUB",
					       imapc_untagged_lsub);
	imapc_list_send_hierarchy_sep_lookup(list);
	return 0;
}

static void imapc_list_deinit(struct mailbox_list *_list)
{
	struct imapc_mailbox_list *list = (struct imapc_mailbox_list *)_list;

	/* make sure all pending commands are aborted before anything is
	   deinitialized */
	if (list->client != NULL) {
		list->client->destroying = TRUE;
		imapc_client_logout(list->client->client);
		imapc_storage_client_unref(&list->client);
	}
	if (list->index_list != NULL)
		mailbox_list_destroy(&list->index_list);
	settings_instance_free(&list->index_list_set_instance);
	mailbox_tree_deinit(&list->mailboxes);
	if (list->tmp_subscriptions != NULL)
		mailbox_tree_deinit(&list->tmp_subscriptions);
	pool_unref(&list->list.pool);
}

static void
imapc_list_copy_error_from_reply(struct imapc_mailbox_list *list,
				 enum mail_error default_error,
				 const struct imapc_command_reply *reply)
{
	enum mail_error error;

	if (imapc_resp_text_code_parse(reply->resp_text_key, &error)) {
		mailbox_list_set_error(&list->list, error,
				       reply->text_without_resp);
	} else {
		mailbox_list_set_error(&list->list, default_error,
				       reply->text_without_resp);
	}
}

static void imapc_list_simple_callback(const struct imapc_command_reply *reply,
				       void *context)
{
	struct imapc_simple_context *ctx = context;

	if (reply->state == IMAPC_COMMAND_STATE_OK)
		ctx->ret = 0;
	else if (reply->state == IMAPC_COMMAND_STATE_NO) {
		imapc_list_copy_error_from_reply(ctx->client->_list,
						 MAIL_ERROR_PARAMS, reply);
		ctx->ret = -1;
	} else if (imapc_storage_client_handle_auth_failure(ctx->client)) {
		ctx->ret = -1;
	} else if (reply->state == IMAPC_COMMAND_STATE_DISCONNECTED) {
		mailbox_list_set_internal_error(&ctx->client->_list->list);
		ctx->ret = -1;
	} else {
		mailbox_list_set_critical(&ctx->client->_list->list,
			"imapc: Command failed: %s", reply->text_full);
		ctx->ret = -1;
	}
	imapc_client_stop(ctx->client->client);
}

static bool
imap_list_flag_parse(const char *str, enum mailbox_info_flags *flag_r)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(imap_list_flags); i++) {
		if (strcasecmp(str, imap_list_flags[i].str) == 0) {
			*flag_r = imap_list_flags[i].flag;
			return TRUE;
		}
	}
	return FALSE;
}

static const char *
imapc_list_remote_to_storage_name(struct imapc_mailbox_list *list,
				  const char *remote_name)
{
	/* typically mailbox_list_escape_name() is used to escape vname into
	   a list name. but we want to convert remote IMAP name to a list name,
	   so we need to use the remote IMAP separator. */
	return mailbox_list_escape_name_params(remote_name, "",
		list->root_sep,
		mailbox_list_get_hierarchy_sep(&list->list),
		list->list.mail_set->mailbox_list_storage_escape_char[0], "");
}

static const char *
imapc_list_remote_to_vname(struct imapc_mailbox_list *list,
			   const char *remote_name)
{
	return mailbox_list_get_vname(&list->list,
		imapc_list_remote_to_storage_name(list, remote_name));
}

const char *
imapc_list_storage_to_remote_name(struct imapc_mailbox_list *list,
				  const char *storage_name)
{
	return mailbox_list_unescape_name_params(storage_name, "",
		list->root_sep, mailbox_list_get_hierarchy_sep(&list->list),
		list->list.mail_set->mailbox_list_storage_escape_char[0]);
}

static struct mailbox_node *
imapc_list_update_tree(struct imapc_mailbox_list *list,
		       struct mailbox_tree_context *tree,
		       const struct imap_arg *args)
{
	struct mailbox_node *node;
	const struct imap_arg *flags;
	const char *remote_name, *flag;
	enum mailbox_info_flags info_flag, info_flags = 0;
	bool created;

	if (!imap_arg_get_list(&args[0], &flags) ||
	    args[1].type == IMAP_ARG_EOL ||
	    !imap_arg_get_astring(&args[2], &remote_name))
		return NULL;

	while (imap_arg_get_atom(flags, &flag)) {
		if (imap_list_flag_parse(flag, &info_flag))
			info_flags |= info_flag;
		flags++;
	}

	T_BEGIN {
		const char *vname =
			imapc_list_remote_to_vname(list, remote_name);
		node = mailbox_tree_get(tree, vname, &created);
		node->flags = info_flags;
	} T_END;

	return node;
}

static void imapc_untagged_list(const struct imapc_untagged_reply *reply,
				struct imapc_storage_client *client)
{
	struct imapc_mailbox_list *list = client->_list;
	const struct imap_arg *args = reply->args;
	const char *sep, *remote_name;

	if (list->root_sep == '\0') {
		/* we haven't asked for the separator yet.
		   lets see if this is the reply for its request. */
		if (args[0].type == IMAP_ARG_EOL ||
		    !imap_arg_get_nstring(&args[1], &sep) ||
		    !imap_arg_get_astring(&args[2], &remote_name))
			return;

		/* we can't handle NIL separator yet */
		list->root_sep = sep == NULL ? '/' : sep[0];
		mailbox_tree_set_separator(list->mailboxes, list->root_sep);
	} else {
		struct mailbox_node *node =
			imapc_list_update_tree(list, list->mailboxes, args);
		if (node != NULL && (node->flags & MAILBOX_SUBSCRIBED) != 0) {
			struct mailbox_tree_context *tree =
				list->tmp_subscriptions != NULL ?
				list->tmp_subscriptions :
				list->list.subscriptions;
			(void)imapc_list_update_tree(list, tree, args);
		}
	}
}

static void imapc_untagged_lsub(const struct imapc_untagged_reply *reply,
				struct imapc_storage_client *client)
{
	struct imapc_mailbox_list *list = client->_list;
	const struct imap_arg *args = reply->args;
	struct mailbox_node *node;

	if (list->root_sep == '\0') {
		/* we haven't asked for the separator yet */
		return;
	}
	struct mailbox_tree_context *tree =
		list->tmp_subscriptions != NULL ?
		list->tmp_subscriptions :
		list->list.subscriptions;
	node = imapc_list_update_tree(list, tree, args);
	if (node != NULL) {
		if ((node->flags & MAILBOX_NOSELECT) == 0)
			node->flags |= MAILBOX_SUBSCRIBED;
		else {
			/* LSUB \Noselect means that the mailbox isn't
			   subscribed, but it has children that are */
			node->flags &= ENUM_NEGATE(MAILBOX_NOSELECT);
		}
	}
}

static void imapc_list_sep_verify(struct imapc_mailbox_list *list)
{
	const char *imapc_list_prefix = list->set->imapc_list_prefix;

	if (list->root_sep == '\0') {
		mailbox_list_set_critical(&list->list,
			"imapc: LIST didn't return hierarchy separator");
	} else if (imapc_list_prefix[0] != '\0' &&
		   imapc_list_prefix[strlen(imapc_list_prefix)-1] == list->root_sep) {
		mailbox_list_set_critical(&list->list,
			"imapc_list_prefix must not end with hierarchy separator");
	}
}

static void imapc_storage_sep_callback(const struct imapc_command_reply *reply,
				       void *context)
{
	struct imapc_mailbox_list *list = context;

	list->root_sep_pending = FALSE;
	if (reply->state == IMAPC_COMMAND_STATE_OK)
		imapc_list_sep_verify(list);
	else if (reply->state == IMAPC_COMMAND_STATE_NO)
		imapc_list_copy_error_from_reply(list, MAIL_ERROR_PARAMS, reply);
	else if (imapc_storage_client_handle_auth_failure(list->client))
		;
	else if (reply->state == IMAPC_COMMAND_STATE_DISCONNECTED)
		mailbox_list_set_internal_error(&list->list);
	else if (!list->list.ns->user->deinitializing) {
		mailbox_list_set_critical(&list->list,
			"imapc: Command failed: %s", reply->text_full);
	}
	imapc_client_stop(list->client->client);
}

static void imapc_list_send_hierarchy_sep_lookup(struct imapc_mailbox_list *list)
{
	struct imapc_command *cmd;

	if (list->root_sep_pending)
		return;
	list->root_sep_pending = TRUE;

	cmd = imapc_client_cmd(list->client->client,
			       imapc_storage_sep_callback, list);
	imapc_command_set_flags(cmd, IMAPC_COMMAND_FLAG_RETRIABLE);
	imapc_command_send(cmd, "LIST \"\" \"\"");
}

int imapc_list_try_get_root_sep(struct imapc_mailbox_list *list, char *sep_r)
{
	if (list->root_sep == '\0') {
		if (imapc_storage_client_handle_auth_failure(list->client))
			return -1;
		imapc_list_send_hierarchy_sep_lookup(list);
		while (list->root_sep_pending)
			imapc_client_run(list->client->client);
		if (list->root_sep == '\0')
			return -1;
	}
	*sep_r = list->root_sep;
	return 0;
}

static char imapc_list_get_hierarchy_sep(struct mailbox_list *_list)
{
	struct imapc_mailbox_list *list = (struct imapc_mailbox_list *)_list;
	char sep;

	if (imapc_list_try_get_root_sep(list, &sep) < 0) {
		/* we can't really return a failure here. just return a common
		   separator and fail all the future list operations. */
		return '/';
	}
	return sep;
}

static const char *
imapc_list_get_storage_name(struct mailbox_list *_list, const char *vname)
{
	struct imapc_mailbox_list *list = (struct imapc_mailbox_list *)_list;
	const char *prefix = list->set->imapc_list_prefix;
	const char *storage_name;

	storage_name = mailbox_list_default_get_storage_name(_list, vname);
	if (*prefix != '\0' && strcasecmp(storage_name, "INBOX") != 0) {
		storage_name = storage_name[0] == '\0' ? prefix :
			t_strdup_printf("%s%c%s", prefix,
			mailbox_list_get_hierarchy_sep(_list),
			storage_name);
	}
	return storage_name;
}

static const char *
imapc_list_get_vname(struct mailbox_list *_list, const char *storage_name)
{
	struct imapc_mailbox_list *list = (struct imapc_mailbox_list *)_list;
	const char *prefix = list->set->imapc_list_prefix;

	if (*storage_name == '\0') {
		/* ACL plugin does these lookups */
	} else if (*prefix != '\0' && strcasecmp(storage_name, "INBOX") != 0) {
		if (!str_begins(storage_name, prefix, &storage_name))
			i_unreached();
		if (storage_name[0] == '\0') {
			/* we're looking up the prefix itself */
		} else {
			i_assert(storage_name[0] ==
				 mailbox_list_get_hierarchy_sep(_list));
			storage_name++;
		}
	}
	return mailbox_list_default_get_vname(_list, storage_name);
}

static struct mailbox_list *imapc_list_get_fs(struct imapc_mailbox_list *list)
{
	const char *error, *dir;

	if (list->list.mail_set->mail_index_path[0] == '\0')
		dir = list->list.mail_set->mail_path;
	else if (strcmp(list->list.mail_set->mail_index_path,
			MAIL_INDEX_PATH_MEMORY) == 0)
		dir = "";
	else
		dir = list->list.mail_set->mail_index_path;

	if (dir[0] == '\0') {
		/* indexes disabled */
	} else if (list->index_list == NULL && !list->index_list_failed) {
		struct settings_instance *set_instance =
			mail_storage_service_user_get_settings_instance(
				list->list.ns->user->service_user);
		list->index_list_set_instance =
			settings_instance_dup(set_instance);
		mail_storage_2nd_settings_reset(list->index_list_set_instance, "*/");
		/* Filesystem needs to be able to store any kind of a mailbox
		   name. */
		settings_override(list->index_list_set_instance,
				  "*/mailbox_list_storage_escape_char",
				  IMAPC_LIST_FS_NAME_ESCAPE_CHAR,
				  SETTINGS_OVERRIDE_TYPE_CODE);
		settings_override(list->index_list_set_instance,
				  "*/mailbox_list_layout",
				  MAILBOX_LIST_NAME_MAILDIRPLUSPLUS,
				  SETTINGS_OVERRIDE_TYPE_CODE);
		settings_override(list->index_list_set_instance,
				  "*/mail_path",
				  list->list.mail_set->mail_path,
				  SETTINGS_OVERRIDE_TYPE_CODE);
		settings_override(list->index_list_set_instance,
				  "*/mail_index_private_path",
				  list->list.mail_set->mail_index_private_path,
				  SETTINGS_OVERRIDE_TYPE_CODE);

		const struct mail_storage_settings *mail_set = NULL;
		struct event *event = event_create(list->list.event);
		event_set_ptr(event, SETTINGS_EVENT_INSTANCE,
			      list->index_list_set_instance);
		settings_event_add_filter_name(event,
			MAILBOX_LIST_NAME_MAILDIRPLUSPLUS);
		if (settings_get(event, &mail_storage_setting_parser_info, 0,
				 &mail_set, &error) < 0) {
			e_error(list->list.event, "%s", error);
			list->index_list_failed = TRUE;
		} else if (mailbox_list_create(event, list->list.ns, mail_set,
					       MAILBOX_LIST_FLAG_SECONDARY,
					       &list->index_list, &error) < 0) {
			e_error(list->list.event,
				"imapc: Couldn't create %s mailbox list: %s",
				MAILBOX_LIST_NAME_MAILDIRPLUSPLUS, error);
			list->index_list_failed = TRUE;
		}
		settings_free(mail_set);
		event_unref(&event);
	}
	return list->index_list;
}

static const char *
imapc_list_storage_to_fs_name(struct imapc_mailbox_list *list,
			      const char *storage_name)
{
	struct mailbox_list *fs_list = imapc_list_get_fs(list);
	const char *remote_name;

	if (storage_name == NULL)
		return NULL;

	remote_name = imapc_list_storage_to_remote_name(list, storage_name);
	return mailbox_list_escape_name_params(remote_name, "",
		list->root_sep, mailbox_list_get_hierarchy_sep(fs_list),
		fs_list->mail_set->mailbox_list_storage_escape_char[0], "");
}

static const char *
imapc_list_fs_to_storage_name(struct imapc_mailbox_list *list,
			      const char *fs_name)
{
	struct mailbox_list *fs_list = imapc_list_get_fs(list);
	const char *remote_name;

	if (fs_name == NULL)
		return NULL;

	remote_name = mailbox_list_unescape_name_params(fs_name, "",
			list->root_sep,
			mailbox_list_get_hierarchy_sep(fs_list),
			fs_list->mail_set->mailbox_list_storage_escape_char[0]);
	return imapc_list_remote_to_storage_name(list, remote_name);
}

static int
imapc_list_get_path(struct mailbox_list *_list, const char *name,
		    enum mailbox_list_path_type type, const char **path_r)
{
	struct imapc_mailbox_list *list = (struct imapc_mailbox_list *)_list;
	struct mailbox_list *fs_list = imapc_list_get_fs(list);
	const char *fs_name;

	if (fs_list != NULL) {
		fs_name = imapc_list_storage_to_fs_name(list, name);
		return mailbox_list_get_path(fs_list, fs_name, type, path_r);
	} else {
		*path_r = NULL;
		return 0;
	}
}

static const char *
imapc_list_get_temp_prefix(struct mailbox_list *_list, bool global)
{
	struct imapc_mailbox_list *list = (struct imapc_mailbox_list *)_list;
	struct mailbox_list *fs_list = imapc_list_get_fs(list);

	if (fs_list != NULL) {
		return global ?
			mailbox_list_get_global_temp_prefix(fs_list) :
			mailbox_list_get_temp_prefix(fs_list);
	} else {
		i_panic("imapc: Can't return a temp prefix for namespace %s",
			_list->ns->set->name);
	}
}

static const char *
imapc_list_join_refpattern(struct mailbox_list *list ATTR_UNUSED,
			   const char *ref, const char *pattern)
{
	return t_strconcat(ref, pattern, NULL);
}

static struct imapc_command *
imapc_list_simple_context_init(struct imapc_simple_context *ctx,
			       struct imapc_mailbox_list *list)
{
	imapc_simple_context_init(ctx, list->client);
	return imapc_client_cmd(list->client->client,
				imapc_list_simple_callback, ctx);
}

static void imapc_list_delete_unused_indexes(struct imapc_mailbox_list *list)
{
	struct mailbox_list *fs_list = imapc_list_get_fs(list);
	struct mailbox_list_iterate_context *iter;
	const struct mailbox_info *info;
	const char *fs_name, *storage_name, *vname;

	if (fs_list == NULL)
		return;

	iter = mailbox_list_iter_init(fs_list, "*",
				      MAILBOX_LIST_ITER_RAW_LIST |
				      MAILBOX_LIST_ITER_NO_AUTO_BOXES |
				      MAILBOX_LIST_ITER_RETURN_NO_FLAGS);
	while ((info = mailbox_list_iter_next(iter)) != NULL) T_BEGIN {
		fs_name = mailbox_list_get_storage_name(fs_list, info->vname);
		storage_name = imapc_list_fs_to_storage_name(list, fs_name);
		vname = mailbox_list_get_vname(&list->list, storage_name);

		/* list->mailboxes contains proper vnames. fs_vname  */
		if (mailbox_tree_lookup(list->mailboxes, vname) == NULL)
			(void)fs_list->v.delete_mailbox(fs_list, fs_name);
	} T_END;
	(void)mailbox_list_iter_deinit(&iter);
}

static int imapc_list_refresh(struct imapc_mailbox_list *list)
{
	struct imapc_command *cmd;
	struct imapc_simple_context ctx;
	struct mailbox_node *node;
	const char *pattern;
	char sep;

	if (imapc_list_try_get_root_sep(list, &sep) < 0)
		return -1;
	if (list->refreshed_mailboxes)
		return 0;
	if ((list->list.ns->flags & NAMESPACE_FLAG_UNUSABLE) != 0) {
		list->refreshed_mailboxes = TRUE;
		list->refreshed_mailboxes_recently = TRUE;
		return 0;
	}

	if (*list->set->imapc_list_prefix == '\0')
		pattern = "*";
	else {
		/* list "prefix*" instead of "prefix.*". this may return a bit
		   more than we want, but we're also interested in the flags
		   of the prefix itself. */
		pattern = t_strdup_printf("%s*", list->set->imapc_list_prefix);
	}

	cmd = imapc_list_simple_context_init(&ctx, list);
	imapc_command_set_flags(cmd, IMAPC_COMMAND_FLAG_RETRIABLE);
	imapc_command_sendf(cmd, "LIST \"\" %s", pattern);
	mailbox_tree_deinit(&list->mailboxes);
	list->mailboxes = mailbox_tree_init(mail_namespace_get_sep(list->list.ns));
	mailbox_tree_set_parents_nonexistent(list->mailboxes);
	imapc_simple_run(&ctx, &cmd);

	if ((list->list.ns->flags & NAMESPACE_FLAG_INBOX_USER) != 0) {
		/* INBOX always exists in IMAP server. since this namespace is
		   marked with inbox=yes, show the INBOX even if
		   imapc_list_prefix doesn't match it */
		bool created;
		node = mailbox_tree_get(list->mailboxes, "INBOX", &created);
		if (*list->set->imapc_list_prefix != '\0') {
			/* this listing didn't include the INBOX itself, but
			   might have included its children. make sure there
			   aren't any extra flags in it (especially
			   \NonExistent) */
			node->flags &= MAILBOX_CHILDREN;
		}
	}

	if (ctx.ret == 0) {
		list->refreshed_mailboxes = TRUE;
		list->refreshed_mailboxes_recently = TRUE;
		list->last_refreshed_mailboxes = ioloop_time;
		imapc_list_delete_unused_indexes(list);
	}
	return ctx.ret;
}

static void
imapc_list_build_match_tree(struct imapc_mailbox_list_iterate_context *ctx)
{
	struct imapc_mailbox_list *list =
		(struct imapc_mailbox_list *)ctx->ctx.list;
	struct mailbox_list_iter_update_context update_ctx;
	struct mailbox_tree_iterate_context *iter;
	struct mailbox_node *node;
	const char *vname;

	i_zero(&update_ctx);
	update_ctx.iter_ctx = &ctx->ctx;
	update_ctx.tree_ctx = ctx->tree;
	update_ctx.glob = ctx->ctx.glob;
	update_ctx.match_parents = TRUE;

	iter = mailbox_tree_iterate_init(list->mailboxes, NULL, 0);
	while ((node = mailbox_tree_iterate_next(iter, &vname)) != NULL) {
		update_ctx.leaf_flags = node->flags;
		mailbox_list_iter_update(&update_ctx, vname);
	}
	mailbox_tree_iterate_deinit(&iter);
}

static struct mailbox_list_iterate_context *
imapc_list_iter_init(struct mailbox_list *_list, const char *const *patterns,
		     enum mailbox_list_iter_flags flags)
{
	struct imapc_mailbox_list *list = (struct imapc_mailbox_list *)_list;
	struct mailbox_list_iterate_context *_ctx;
	struct imapc_mailbox_list_iterate_context *ctx;
	pool_t pool;
	const char *ns_root_name;
	char ns_sep;
	int ret = 0;

	if ((flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) == 0 ||
	    (flags & MAILBOX_LIST_ITER_RETURN_NO_FLAGS) == 0)
		ret = imapc_list_refresh(list);

	list->iter_count++;

	if ((flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) != 0) {
		/* we're listing only subscriptions. just use the cached
		   subscriptions list. */
		_ctx = mailbox_list_subscriptions_iter_init(_list, patterns,
							    flags);
		if (ret < 0)
			_ctx->failed = TRUE;
		return _ctx;
	}

	/* if we've already failed, make sure we don't call
	   mailbox_list_get_hierarchy_sep(), since it clears the error */
	ns_sep = ret < 0 ? '/' : mail_namespace_get_sep(_list->ns);

	pool = pool_alloconly_create("mailbox list imapc iter", 1024);
	ctx = p_new(pool, struct imapc_mailbox_list_iterate_context, 1);
	ctx->ctx.pool = pool;
	ctx->ctx.list = _list;
	ctx->ctx.flags = flags;
	ctx->ctx.glob = imap_match_init_multiple(pool, patterns, FALSE, ns_sep);
	array_create(&ctx->ctx.module_contexts, pool, sizeof(void *), 5);

	ctx->info.ns = _list->ns;

	ctx->tree = mailbox_tree_init(ns_sep);
	mailbox_tree_set_parents_nonexistent(ctx->tree);
	if (ret == 0)
		imapc_list_build_match_tree(ctx);

	if (list->list.ns->prefix_len > 0) {
		ns_root_name = t_strndup(_list->ns->prefix,
					 _list->ns->prefix_len - 1);
		ctx->ns_root = mailbox_tree_lookup(ctx->tree, ns_root_name);
	}

	ctx->iter = mailbox_tree_iterate_init(ctx->tree, NULL, 0);
	if (ret < 0)
		ctx->ctx.failed = TRUE;
	return &ctx->ctx;
}

static void
imapc_list_write_special_use(struct imapc_mailbox_list_iterate_context *ctx,
			     struct mailbox_node *node)
{
	unsigned int i;

	if (ctx->special_use == NULL)
		ctx->special_use = str_new(ctx->ctx.pool, 64);
	str_truncate(ctx->special_use, 0);

	for (i = 0; i < N_ELEMENTS(imap_list_flags); i++) {
		if ((node->flags & imap_list_flags[i].flag) != 0 &&
		    (node->flags & MAILBOX_SPECIALUSE_MASK) != 0) {
			str_append(ctx->special_use, imap_list_flags[i].str);
			str_append_c(ctx->special_use, ' ');
		}
	}

	if (str_len(ctx->special_use) > 0) {
		str_truncate(ctx->special_use, str_len(ctx->special_use) - 1);
		ctx->info.special_use = str_c(ctx->special_use);
	} else {
		ctx->info.special_use = NULL;
	}
}

static bool
imapc_list_is_ns_root(struct imapc_mailbox_list_iterate_context *ctx,
		      struct mailbox_node *node)
{
	struct mailbox_node *root_node = ctx->ns_root;

	while (root_node != NULL) {
		if (node == root_node)
			return TRUE;
		root_node = root_node->parent;
	}
	return FALSE;
}

static const struct mailbox_info *
imapc_list_iter_next(struct mailbox_list_iterate_context *_ctx)
{
	struct imapc_mailbox_list_iterate_context *ctx =
		(struct imapc_mailbox_list_iterate_context *)_ctx;
	struct imapc_mailbox_list *list =
		(struct imapc_mailbox_list *)_ctx->list;
	struct mailbox_node *node;
	const char *vname;

	if (_ctx->failed)
		return NULL;

	if ((_ctx->flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) != 0)
		return mailbox_list_subscriptions_iter_next(_ctx);

	do {
		node = mailbox_tree_iterate_next(ctx->iter, &vname);
		if (node == NULL)
			return mailbox_list_iter_default_next(_ctx);
	} while ((node->flags & MAILBOX_MATCHED) == 0 ||
		 (imapc_list_is_ns_root(ctx, node) &&
		  (strcasecmp(vname, "INBOX") != 0 ||
		   (ctx->info.ns->flags & NAMESPACE_FLAG_INBOX_ANY) == 0)));

	if (ctx->info.ns->prefix_len > 0 &&
	    strcasecmp(vname, "INBOX") != 0 &&
	    strncmp(vname, ctx->info.ns->prefix, ctx->info.ns->prefix_len-1) == 0 &&
	    vname[ctx->info.ns->prefix_len] == '\0' &&
	    list->set->imapc_list_prefix[0] == '\0') {
		/* don't return "" name */
		return imapc_list_iter_next(_ctx);
	}

	ctx->info.vname = vname;
	ctx->info.flags = node->flags;
	if ((_ctx->list->ns->flags & NAMESPACE_FLAG_INBOX_USER) != 0) {
		/* we're iterating the INBOX namespace. pass through the
		   SPECIAL-USE flags if they exist. */
		imapc_list_write_special_use(ctx, node);
	} else {
		ctx->info.special_use = NULL;
	}
	return &ctx->info;
}

static int imapc_list_iter_deinit(struct mailbox_list_iterate_context *_ctx)
{
	struct imapc_mailbox_list_iterate_context *ctx =
		(struct imapc_mailbox_list_iterate_context *)_ctx;
	struct imapc_mailbox_list *list =
		(struct imapc_mailbox_list *)_ctx->list;
	int ret = _ctx->failed ? -1 : 0;

	i_assert(list->iter_count > 0);

	if (--list->iter_count == 0) {
		list->refreshed_mailboxes = FALSE;
		list->refreshed_subscriptions = FALSE;
	}

	if ((_ctx->flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) != 0)
		return mailbox_list_subscriptions_iter_deinit(_ctx);

	mailbox_tree_iterate_deinit(&ctx->iter);
	mailbox_tree_deinit(&ctx->tree);
	pool_unref(&_ctx->pool);
	return ret;
}

static int
imapc_list_subscriptions_refresh(struct mailbox_list *_src_list,
				 struct mailbox_list *dest_list)
{
	struct imapc_mailbox_list *src_list =
		(struct imapc_mailbox_list *)_src_list;
	struct imapc_simple_context ctx;
	struct imapc_command *cmd;
	const char *pattern;
	char list_sep, dest_sep = mail_namespace_get_sep(dest_list->ns);

	i_assert(src_list->tmp_subscriptions == NULL);

	if (imapc_list_try_get_root_sep(src_list, &list_sep) < 0)
		return -1;

	if (src_list->refreshed_subscriptions ||
	    (src_list->list.ns->flags & NAMESPACE_FLAG_UNUSABLE) != 0) {
		if (dest_list->subscriptions == NULL)
			dest_list->subscriptions = mailbox_tree_init(dest_sep);
		return 0;
	}

	src_list->tmp_subscriptions =
		mailbox_tree_init(mail_namespace_get_sep(_src_list->ns));

	cmd = imapc_list_simple_context_init(&ctx, src_list);
	if (*src_list->set->imapc_list_prefix == '\0')
		pattern = "*";
	else
		pattern = t_strdup_printf("%s*", src_list->set->imapc_list_prefix);
	imapc_command_set_flags(cmd, IMAPC_COMMAND_FLAG_RETRIABLE);

	if (imapc_cmd_has_imap4rev2(cmd))
		imapc_command_sendf(cmd, "LIST (SUBSCRIBED) \"\" %s", pattern);
	else
		imapc_command_sendf(cmd, "LSUB \"\" %s", pattern);
	imapc_simple_run(&ctx, &cmd);

	if (ctx.ret < 0)
		return -1;

	/* replace subscriptions tree in destination */
	if (dest_list->subscriptions != NULL)
		mailbox_tree_deinit(&dest_list->subscriptions);
	dest_list->subscriptions = src_list->tmp_subscriptions;
	src_list->tmp_subscriptions = NULL;
	mailbox_tree_set_separator(dest_list->subscriptions, dest_sep);

	src_list->refreshed_subscriptions = TRUE;
	return 0;
}

static int imapc_list_set_subscribed(struct mailbox_list *_list,
				     const char *name, bool set)
{
	struct imapc_mailbox_list *list = (struct imapc_mailbox_list *)_list;
	struct imapc_command *cmd;
	struct imapc_simple_context ctx;

	cmd = imapc_list_simple_context_init(&ctx, list);
	imapc_command_set_flags(cmd, IMAPC_COMMAND_FLAG_RETRIABLE);
	imapc_command_sendf(cmd, set ? "SUBSCRIBE %s" : "UNSUBSCRIBE %s",
			    imapc_list_storage_to_remote_name(list, name));
	imapc_simple_run(&ctx, &cmd);
	return ctx.ret;
}

static int
imapc_list_delete_mailbox(struct mailbox_list *_list, const char *name)
{
	struct imapc_mailbox_list *list = (struct imapc_mailbox_list *)_list;
	struct mailbox_list *fs_list = imapc_list_get_fs(list);
	enum imapc_capability capa;
	struct imapc_command *cmd;
	struct imapc_simple_context ctx;

	if (imapc_storage_client_handle_auth_failure(list->client))
		return -1;
	if (imapc_client_get_capabilities(list->client->client, &capa) < 0)
		return -1;

	cmd = imapc_list_simple_context_init(&ctx, list);
	imapc_command_set_flags(cmd, IMAPC_COMMAND_FLAG_RETRIABLE);
	if (!imapc_command_connection_is_selected(cmd))
		imapc_command_abort(&cmd);
	else {
		imapc_command_set_flags(cmd, IMAPC_COMMAND_FLAG_SELECT);
		if ((capa & IMAPC_CAPABILITY_UNSELECT) != 0)
			imapc_command_sendf(cmd, "UNSELECT");
		else
			imapc_command_sendf(cmd, "SELECT \"~~~\"");
		imapc_simple_run(&ctx, &cmd);
	}

	cmd = imapc_list_simple_context_init(&ctx, list);
	imapc_command_set_flags(cmd, IMAPC_COMMAND_FLAG_RETRIABLE);
	imapc_command_sendf(cmd, "DELETE %s", imapc_list_storage_to_remote_name(list, name));
	imapc_simple_run(&ctx, &cmd);

	if (fs_list != NULL && ctx.ret == 0) {
		const char *fs_name = imapc_list_storage_to_fs_name(list, name);
		(void)fs_list->v.delete_mailbox(fs_list, fs_name);
	}
	return ctx.ret;
}

static int
imapc_list_delete_dir(struct mailbox_list *_list, const char *name)
{
	struct imapc_mailbox_list *list = (struct imapc_mailbox_list *)_list;
	struct mailbox_list *fs_list = imapc_list_get_fs(list);

	if (fs_list != NULL) {
		const char *fs_name = imapc_list_storage_to_fs_name(list, name);
		(void)mailbox_list_delete_dir(fs_list, fs_name);
	}
	return 0;
}

static int
imapc_list_delete_symlink(struct mailbox_list *list,
			  const char *name ATTR_UNUSED)
{
	mailbox_list_set_error(list, MAIL_ERROR_NOTPOSSIBLE, "Not supported");
	return -1;
}

static int
imapc_list_rename_mailbox(struct mailbox_list *oldlist, const char *oldname,
			  struct mailbox_list *newlist, const char *newname)
{
	struct imapc_mailbox_list *list = (struct imapc_mailbox_list *)oldlist;
	struct mailbox_list *fs_list = imapc_list_get_fs(list);
	struct imapc_command *cmd;
	struct imapc_simple_context ctx;

	if (oldlist != newlist) {
		mailbox_list_set_error(oldlist, MAIL_ERROR_NOTPOSSIBLE,
			"Can't rename mailboxes across storages.");
		return -1;
	}

	cmd = imapc_list_simple_context_init(&ctx, list);
	imapc_command_sendf(cmd, "RENAME %s %s",
			    imapc_list_storage_to_remote_name(list, oldname),
			    imapc_list_storage_to_remote_name(list, newname));
	imapc_simple_run(&ctx, &cmd);
	if (ctx.ret == 0 && fs_list != NULL && oldlist == newlist) {
		const char *old_fs_name =
			imapc_list_storage_to_fs_name(list, oldname);
		const char *new_fs_name =
			imapc_list_storage_to_fs_name(list, newname);
		(void)fs_list->v.rename_mailbox(fs_list, old_fs_name,
						fs_list, new_fs_name);
	}
	return ctx.ret;
}

int imapc_list_get_mailbox_flags(struct mailbox_list *_list, const char *name,
				 enum mailbox_info_flags *flags_r)
{
	struct imapc_mailbox_list *list = (struct imapc_mailbox_list *)_list;
	struct mailbox_node *node;
	const char *vname;

	vname = mailbox_list_get_vname(_list, name);
	if (!list->refreshed_mailboxes_recently) {
		if (imapc_list_refresh(list) < 0)
			return -1;
		i_assert(list->refreshed_mailboxes_recently);
	}

	if (list->mailboxes == NULL) {
		/* imapc list isn't used, but e.g. mailbox_list_layout=none */
		*flags_r = 0;
		return 0;
	}
	node = mailbox_tree_lookup(list->mailboxes, vname);
	if (node == NULL)
		*flags_r = MAILBOX_NONEXISTENT;
	else
		*flags_r = node->flags;
	return 0;
}

struct mailbox_list imapc_mailbox_list = {
	.name = MAILBOX_LIST_NAME_IMAPC,
	.props = MAILBOX_LIST_PROP_NO_ROOT | MAILBOX_LIST_PROP_AUTOCREATE_DIRS |
		 MAILBOX_LIST_PROP_NO_LIST_INDEX,
	.mailbox_name_max_length = MAILBOX_LIST_NAME_MAX_LENGTH,

	.v = {
		.alloc = imapc_list_alloc,
		.init = imapc_list_init,
		.deinit = imapc_list_deinit,
		.get_storage = mailbox_list_default_get_storage,
		.get_hierarchy_sep = imapc_list_get_hierarchy_sep,
		.get_vname = imapc_list_get_vname,
		.get_storage_name = imapc_list_get_storage_name,
		.get_path = imapc_list_get_path,
		.get_temp_prefix = imapc_list_get_temp_prefix,
		.join_refpattern = imapc_list_join_refpattern,
		.iter_init = imapc_list_iter_init,
		.iter_next = imapc_list_iter_next,
		.iter_deinit = imapc_list_iter_deinit,
		.subscriptions_refresh = imapc_list_subscriptions_refresh,
		.set_subscribed = imapc_list_set_subscribed,
		.delete_mailbox = imapc_list_delete_mailbox,
		.delete_dir = imapc_list_delete_dir,
		.delete_symlink = imapc_list_delete_symlink,
		.rename_mailbox = imapc_list_rename_mailbox,
	}
};
