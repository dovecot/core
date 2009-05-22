/* Copyright (C) 2007-2008 Timo Sirainen, LGPLv2.1 */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "module-context.h"
#include "mail-storage-private.h"
#include "mailbox-list-private.h"
#include "listescape-plugin.h"

#include <stdlib.h>
#include <ctype.h>

#define DEFAULT_ESCAPE_CHAR '\\'

#define LIST_ESCAPE_CONTEXT(obj) \
	MODULE_CONTEXT(obj, listescape_storage_module)
#define LIST_ESCAPE_LIST_CONTEXT(obj) \
	MODULE_CONTEXT(obj, listescape_list_module)

struct listescape_mail_storage {
	union mail_storage_module_context module_ctx;
};

struct listescape_mailbox_list {
	union mailbox_list_module_context module_ctx;
	struct mailbox_info info;
	string_t *list_name;
	char escape_char;
	bool name_escaped;
};

const char *listescape_plugin_version = PACKAGE_VERSION;

static void (*listescape_next_hook_mail_storage_created)
	(struct mail_storage *storage);
static void (*listescape_next_hook_mailbox_list_created)
	(struct mailbox_list *list);
static void (*listescape_next_hook_mail_namespaces_created)
	(struct mail_namespace *namespaces);

static MODULE_CONTEXT_DEFINE_INIT(listescape_storage_module,
				  &mail_storage_module_register);
static MODULE_CONTEXT_DEFINE_INIT(listescape_list_module,
				  &mailbox_list_module_register);

static const char *list_escape(struct mail_namespace *ns,
			       const char *str, bool change_sep)
{
	struct listescape_mailbox_list *mlist =
		LIST_ESCAPE_LIST_CONTEXT(ns->list);
	string_t *esc = t_str_new(64);

	if (*str == '~') {
		str_printfa(esc, "%c%02x", mlist->escape_char, *str);
		str++;
	}
	for (; *str != '\0'; str++) {
		if (*str == ns->sep && change_sep)
			str_append_c(esc, ns->list->hierarchy_sep);
		else if (*str == ns->list->hierarchy_sep ||
			 *str == mlist->escape_char || *str == '/')
			str_printfa(esc, "%c%02x", mlist->escape_char, *str);
		else
			str_append_c(esc, *str);
	}
	return str_c(esc);
}

static void list_unescape_str(struct mail_namespace *ns,
			      const char *str, string_t *dest)
{
	struct listescape_mailbox_list *mlist =
		LIST_ESCAPE_LIST_CONTEXT(ns->list);
	unsigned int num;

	for (; *str != '\0'; str++) {
		if (*str == mlist->escape_char &&
		    i_isxdigit(str[1]) && i_isxdigit(str[2])) {
			if (str[1] >= '0' && str[1] <= '9')
				num = str[1] - '0';
			else
				num = i_toupper(str[1]) - 'A' + 10;
			num *= 16;
			if (str[2] >= '0' && str[2] <= '9')
				num += str[2] - '0';
			else
				num += i_toupper(str[2]) - 'A' + 10;

			str_append_c(dest, num);
			str += 2;
		} else if (*str == ns->list->hierarchy_sep)
			str_append_c(dest, ns->sep);
		else
			str_append_c(dest, *str);
	}
}

static struct mailbox_list_iterate_context *
listescape_mailbox_list_iter_init(struct mailbox_list *list,
				  const char *const *patterns,
				  enum mailbox_list_iter_flags flags)
{
	struct listescape_mailbox_list *mlist = LIST_ESCAPE_LIST_CONTEXT(list);
	struct mailbox_list_iterate_context *ctx;
	const char **escaped_patterns;
	unsigned int i;

	t_push();
	if ((flags & MAILBOX_LIST_ITER_VIRTUAL_NAMES) != 0) {
		escaped_patterns = t_new(const char *,
					 str_array_length(patterns) + 1);
		for (i = 0; patterns[i] != NULL; i++) {
			escaped_patterns[i] =
				list_escape(list->ns, patterns[i], FALSE);
		}
		patterns = escaped_patterns;
	}

	/* Listing breaks if ns->real_sep isn't correct, but with everything
	   else we need real_sep == virtual_sep. maybe some day lib-storage
	   API gets changed so that it sees only virtual mailbox names and
	   convers them internally and we don't have this problem. */
	list->ns->real_sep = list->hierarchy_sep;
	ctx = mlist->module_ctx.super.iter_init(list, patterns, flags);
	list->ns->real_sep = list->ns->sep;
	t_pop();
	return ctx;
}

static const struct mailbox_info *
listescape_mailbox_list_iter_next(struct mailbox_list_iterate_context *ctx)
{
	struct listescape_mailbox_list *mlist =
		LIST_ESCAPE_LIST_CONTEXT(ctx->list);
	const struct mailbox_info *info;

	ctx->list->ns->real_sep = ctx->list->hierarchy_sep;
	info = mlist->module_ctx.super.iter_next(ctx);
	ctx->list->ns->real_sep = ctx->list->ns->sep;
	if (info == NULL || (ctx->flags & MAILBOX_LIST_ITER_VIRTUAL_NAMES) == 0)
		return info;

	str_truncate(mlist->list_name, 0);
	list_unescape_str(ctx->list->ns, info->name, mlist->list_name);
	mlist->info = *info;
	mlist->info.name = str_c(mlist->list_name);
	return &mlist->info;
}

static int
listescape_mailbox_list_iter_deinit(struct mailbox_list_iterate_context *ctx)
{
	struct mailbox_list *list = ctx->list;
	struct listescape_mailbox_list *mlist =
		LIST_ESCAPE_LIST_CONTEXT(ctx->list);
	int ret;

	list->ns->real_sep = list->hierarchy_sep;
	ret = mlist->module_ctx.super.iter_deinit(ctx);
	list->ns->real_sep = list->ns->sep;
	return ret;
}

static struct mailbox *
listescape_mailbox_open(struct mail_storage *storage, const char *name,
			struct istream *input, enum mailbox_open_flags flags)
{
	struct listescape_mail_storage *mstorage =
		LIST_ESCAPE_CONTEXT(storage);
	struct listescape_mailbox_list *mlist =
		LIST_ESCAPE_LIST_CONTEXT(storage->list);

	if (!mlist->name_escaped)
		name = list_escape(storage->ns, name, TRUE);
	return mstorage->module_ctx.super.
		mailbox_open(storage, name, input, flags);
}

static int
listescape_mailbox_create(struct mail_storage *storage, const char *name,
			  bool directory)
{
	struct listescape_mail_storage *mstorage =
		LIST_ESCAPE_CONTEXT(storage);

	name = list_escape(storage->ns, name, TRUE);
	return mstorage->module_ctx.super.
		mailbox_create(storage, name, directory);
}

static int
listescape_delete_mailbox(struct mailbox_list *list, const char *name)
{
	struct listescape_mailbox_list *mlist = LIST_ESCAPE_LIST_CONTEXT(list);
	int ret;

	/* at least quota plugin opens the mailbox when deleting it */
	name = list_escape(list->ns, name, TRUE);
	mlist->name_escaped = TRUE;
	ret = mlist->module_ctx.super.delete_mailbox(list, name);
	mlist->name_escaped = FALSE;
	return ret;
}

static int
listescape_rename_mailbox(struct mailbox_list *oldlist, const char *oldname,
			  struct mailbox_list *newlist, const char *newname,
			  bool rename_children)
{
	struct listescape_mailbox_list *old_mlist =
		LIST_ESCAPE_LIST_CONTEXT(oldlist);

	oldname = list_escape(oldlist->ns, oldname, TRUE);
	newname = list_escape(newlist->ns, newname, TRUE);
	return old_mlist->module_ctx.super.
		rename_mailbox(oldlist, oldname, newlist, newname,
			       rename_children);
}

static int listescape_set_subscribed(struct mailbox_list *list, 
				     const char *name, bool set)
{
	struct listescape_mailbox_list *mlist = LIST_ESCAPE_LIST_CONTEXT(list);

	name = list_escape(list->ns, name, TRUE);
	return mlist->module_ctx.super.set_subscribed(list, name, set);
}

static int listescape_get_mailbox_name_status(struct mailbox_list *list,
					      const char *name,
					      enum mailbox_name_status *status)
{
	struct listescape_mailbox_list *mlist = LIST_ESCAPE_LIST_CONTEXT(list);

	name = list_escape(list->ns, name, TRUE);
	return mlist->module_ctx.super.
		get_mailbox_name_status(list, name, status);
}

static bool listescape_is_valid_existing_name(struct mailbox_list *list,
					      const char *name)
{
	struct listescape_mailbox_list *mlist = LIST_ESCAPE_LIST_CONTEXT(list);

	name = list_escape(list->ns, name, TRUE);
	return mlist->module_ctx.super.is_valid_existing_name(list, name);
}

static bool listescape_is_valid_create_name(struct mailbox_list *list,
					    const char *name)
{
	struct listescape_mailbox_list *mlist = LIST_ESCAPE_LIST_CONTEXT(list);

	name = list_escape(list->ns, name, TRUE);
	return mlist->module_ctx.super.is_valid_create_name(list, name);
}

static void listescape_mail_storage_created(struct mail_storage *storage)
{
	struct listescape_mail_storage *mstorage;

	if (listescape_next_hook_mail_storage_created != NULL)
		listescape_next_hook_mail_storage_created(storage);

	if (storage->list->hierarchy_sep == storage->ns->sep)
		return;

	mstorage = p_new(storage->pool, struct listescape_mail_storage, 1);
	mstorage->module_ctx.super = storage->v;
	storage->v.mailbox_open = listescape_mailbox_open;
	storage->v.mailbox_create = listescape_mailbox_create;

	MODULE_CONTEXT_SET(storage, listescape_storage_module, mstorage);
}

static void listescape_mailbox_list_created(struct mailbox_list *list)
{
	struct listescape_mailbox_list *mlist;
	const char *env;

	if (listescape_next_hook_mailbox_list_created != NULL)
		listescape_next_hook_mailbox_list_created(list);

	if (list->hierarchy_sep == list->ns->sep)
		return;

	mlist = p_new(list->pool, struct listescape_mailbox_list, 1);
	mlist->module_ctx.super = list->v;
	mlist->list_name = str_new(list->pool, 256);
	list->v.iter_init = listescape_mailbox_list_iter_init;
	list->v.iter_next = listescape_mailbox_list_iter_next;
	list->v.iter_deinit = listescape_mailbox_list_iter_deinit;
	list->v.delete_mailbox = listescape_delete_mailbox;
	list->v.rename_mailbox = listescape_rename_mailbox;
	list->v.set_subscribed = listescape_set_subscribed;
	list->v.get_mailbox_name_status = listescape_get_mailbox_name_status;
	list->v.is_valid_existing_name = listescape_is_valid_existing_name;
	list->v.is_valid_create_name = listescape_is_valid_create_name;

	env = mail_user_plugin_getenv(list->ns->user, "listescape_char");
	mlist->escape_char = env != NULL && *env != '\0' ?
		env[0] : DEFAULT_ESCAPE_CHAR;

	MODULE_CONTEXT_SET(list, listescape_list_module, mlist);
}

static void
listescape_mail_namespaces_created(struct mail_namespace *namespaces)
{
	struct mail_namespace *ns = namespaces;

	for (ns = namespaces; ns != NULL; ns = ns->next) {
		if (ns->real_sep != ns->sep)
			ns->real_sep = ns->sep;
	}

	if (listescape_next_hook_mail_namespaces_created != NULL)
		listescape_next_hook_mail_namespaces_created(namespaces);
}

void listescape_plugin_init(void)
{
	listescape_next_hook_mail_storage_created = hook_mail_storage_created;
	hook_mail_storage_created = listescape_mail_storage_created;

	listescape_next_hook_mailbox_list_created = hook_mailbox_list_created;
	hook_mailbox_list_created = listescape_mailbox_list_created;

	listescape_next_hook_mail_namespaces_created =
		hook_mail_namespaces_created;
	hook_mail_namespaces_created = listescape_mail_namespaces_created;
}

void listescape_plugin_deinit(void)
{
	hook_mail_storage_created = listescape_next_hook_mail_storage_created;
	hook_mailbox_list_created = listescape_next_hook_mailbox_list_created;
	hook_mail_namespaces_created =
		listescape_next_hook_mail_namespaces_created;
}
