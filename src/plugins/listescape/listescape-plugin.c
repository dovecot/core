/* Copyright (c) 2007-2011 Dovecot authors, see the included COPYING file */

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

struct listescape_mailbox_list_iter {
	struct mailbox_list_iterate_context *ctx;
	string_t *name;
	struct mailbox_info info;
};

struct listescape_mailbox_list {
	union mailbox_list_module_context module_ctx;
	ARRAY_DEFINE(iters, struct listescape_mailbox_list_iter);
	char escape_char;
};

const char *listescape_plugin_version = DOVECOT_VERSION;

static MODULE_CONTEXT_DEFINE_INIT(listescape_storage_module,
				  &mail_storage_module_register);
static MODULE_CONTEXT_DEFINE_INIT(listescape_list_module,
				  &mailbox_list_module_register);

static const char *
list_escape(struct listescape_mailbox_list *mlist,
	    struct mail_namespace *ns, const char *str, bool vname)
{
	string_t *esc = t_str_new(64);
	unsigned int i;

	for (i = 0; str[i] != '\0'; i++) {
		if (str[i] == '*' || str[i] == '%')
			break;
	}
	if (i > ns->prefix_len)
		i = ns->prefix_len;

	if (vname && i > 0 && strncmp(ns->prefix, str, i) == 0) {
		str_append_n(esc, str, i);
		str += i;
	}

	if (*str == '~') {
		str_printfa(esc, "%c%02x", mlist->escape_char, *str);
		str++;
	}
	for (; *str != '\0'; str++) {
		if (*str == ns->sep) {
			if (!vname)
				str_append_c(esc, ns->list->hierarchy_sep);
			else
				str_append_c(esc, *str);
		} else if (*str == ns->list->hierarchy_sep ||
			   *str == mlist->escape_char || *str == '/')
			str_printfa(esc, "%c%02x", mlist->escape_char, *str);
		else
			str_append_c(esc, *str);
	}
	return str_c(esc);
}

static void list_unescape_str(struct listescape_mailbox_list *mlist,
			      struct mail_namespace *ns,
			      const char *str, string_t *dest)
{
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

static struct mail_namespace *
listescape_find_orig_ns(struct mail_namespace *parent_ns, const char *name)
{
	struct mail_namespace *ns, *best = NULL;

	for (ns = parent_ns->user->namespaces; ns != NULL; ns = ns->next) {
		if ((ns->flags & NAMESPACE_FLAG_SUBSCRIPTIONS) != 0)
			continue;

		if (strncmp(ns->prefix, parent_ns->prefix,
			    parent_ns->prefix_len) == 0 &&
		    strncmp(ns->prefix + parent_ns->prefix_len, name,
			    ns->prefix_len) == 0) {
			if (best == NULL || ns->prefix_len > best->prefix_len)
				best = ns;
		}
	}
	return best != NULL ? best : parent_ns;
}

static const char *const *
iter_escape_patterns(struct mailbox_list *list,
		     const char *const *patterns,
		     enum mailbox_list_iter_flags flags)
{
	struct listescape_mailbox_list *mlist = LIST_ESCAPE_LIST_CONTEXT(list);
	struct mail_namespace *orig_ns;
	const char **escaped_patterns;
	unsigned int i;

	escaped_patterns = t_new(const char *, str_array_length(patterns) + 1);
	for (i = 0; patterns[i] != NULL; i++) {
		if ((flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) != 0) {
			/* we may be listing subscriptions for other namespaces
			   prefixes. don't escape characters in the namespace
			   prefixes. */
			orig_ns = listescape_find_orig_ns(list->ns,
							  patterns[i]);
		} else {
			orig_ns = list->ns;
		}
		escaped_patterns[i] = list_escape(mlist, orig_ns,
						  patterns[i], TRUE);
	}
	return escaped_patterns;
}

static struct mailbox_list_iterate_context *
listescape_mailbox_list_iter_init(struct mailbox_list *list,
				  const char *const *patterns,
				  enum mailbox_list_iter_flags flags)
{
	struct listescape_mailbox_list *mlist = LIST_ESCAPE_LIST_CONTEXT(list);
	struct mailbox_list_iterate_context *ctx;
	struct listescape_mailbox_list_iter *liter;

	/* this is kind of kludgy. In ACL code we want to convert patterns,
	   in maildir renaming code we don't. so for now just use the _RAW_LIST
	   flag.. */
	if ((flags & MAILBOX_LIST_ITER_RAW_LIST) == 0)
		patterns = iter_escape_patterns(list, patterns, flags);

	/* Listing breaks if ns->real_sep isn't correct, but with everything
	   else we need real_sep == virtual_sep. maybe some day lib-storage
	   API gets changed so that it sees only virtual mailbox names and
	   convers them internally and we don't have this problem. */
	list->ns->real_sep = list->hierarchy_sep;
	ctx = mlist->module_ctx.super.iter_init(list, patterns, flags);
	list->ns->real_sep = list->ns->sep;

	liter = array_append_space(&mlist->iters);
	liter->ctx = ctx;
	liter->name = str_new(default_pool, 256);
	return ctx;
}

static struct listescape_mailbox_list_iter *
listescape_mailbox_list_iter_find(struct listescape_mailbox_list *mlist,
				 struct mailbox_list_iterate_context *ctx)
{
	struct listescape_mailbox_list_iter *liter;

	array_foreach_modifiable(&mlist->iters, liter) {
		if (liter->ctx == ctx)
			return liter;
	}
	return NULL;
}

static const struct mailbox_info *
listescape_mailbox_list_iter_next(struct mailbox_list_iterate_context *ctx)
{
	struct listescape_mailbox_list *mlist =
		LIST_ESCAPE_LIST_CONTEXT(ctx->list);
	struct mail_namespace *ns;
	struct listescape_mailbox_list_iter *liter;
	const struct mailbox_info *info;

	liter = listescape_mailbox_list_iter_find(mlist, ctx);
	i_assert(liter != NULL);

	ctx->list->ns->real_sep = ctx->list->hierarchy_sep;
	info = mlist->module_ctx.super.iter_next(ctx);
	ctx->list->ns->real_sep = ctx->list->ns->sep;
	if (info == NULL)
		return info;

	ns = (ctx->flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) == 0 ?
		ctx->list->ns :
		listescape_find_orig_ns(ctx->list->ns, info->name);

	if ((ns->flags & NAMESPACE_FLAG_INBOX_USER) != 0 &&
	    strcasecmp(info->name, "INBOX") == 0)
		return info;

	str_truncate(liter->name, 0);
	str_append(liter->name, ns->prefix);
	list_unescape_str(mlist, ns, info->name + ns->prefix_len, liter->name);
	liter->info = *info;
	liter->info.name = str_c(liter->name);
	return &liter->info;
}

static int
listescape_mailbox_list_iter_deinit(struct mailbox_list_iterate_context *ctx)
{
	struct mailbox_list *list = ctx->list;
	struct listescape_mailbox_list *mlist =
		LIST_ESCAPE_LIST_CONTEXT(ctx->list);
	struct listescape_mailbox_list_iter *liters;
	unsigned int i, count;
	int ret;

	liters = array_get_modifiable(&mlist->iters, &count);
	for (i = 0; i < count; i++) {
		if (liters[i].ctx == ctx) {
			str_free(&liters[i].name);
			array_delete(&mlist->iters, i, 1);
		}
	}

	list->ns->real_sep = list->hierarchy_sep;
	ret = mlist->module_ctx.super.iter_deinit(ctx);
	list->ns->real_sep = list->ns->sep;
	return ret;
}

static struct mailbox *
listescape_mailbox_alloc(struct mail_storage *storage,
			 struct mailbox_list *list,
			 const char *name, enum mailbox_flags flags)
{
	struct listescape_mail_storage *mstorage = LIST_ESCAPE_CONTEXT(storage);
	struct listescape_mailbox_list *mlist = LIST_ESCAPE_LIST_CONTEXT(list);

	if (list->hierarchy_sep != list->ns->sep)
		name = list_escape(mlist, list->ns, name, FALSE);
	return mstorage->module_ctx.super.
		mailbox_alloc(storage, list, name, flags);
}

static int listescape_set_subscribed(struct mailbox_list *list, 
				     const char *name, bool set)
{
	struct listescape_mailbox_list *mlist = LIST_ESCAPE_LIST_CONTEXT(list);
	struct mail_namespace *ns;
	const char *esc_name;

	ns = listescape_find_orig_ns(list->ns, name);
	if (ns == list->ns || strncmp(ns->prefix, name, ns->prefix_len) != 0)
		name = list_escape(mlist, ns, name, FALSE);
	else {
		esc_name = list_escape(mlist, ns, name + ns->prefix_len, FALSE);
		name = t_strconcat(ns->prefix, esc_name, NULL);
	}
	return mlist->module_ctx.super.set_subscribed(list, name, set);
}

static int listescape_get_mailbox_name_status(struct mailbox_list *list,
					      const char *name,
					      enum mailbox_name_status *status)
{
	struct listescape_mailbox_list *mlist = LIST_ESCAPE_LIST_CONTEXT(list);

	name = list_escape(mlist, list->ns, name, FALSE);
	return mlist->module_ctx.super.
		get_mailbox_name_status(list, name, status);
}

static bool listescape_is_valid_existing_name(struct mailbox_list *list,
					      const char *name)
{
	struct listescape_mailbox_list *mlist = LIST_ESCAPE_LIST_CONTEXT(list);

	name = list_escape(mlist, list->ns, name, FALSE);
	return mlist->module_ctx.super.is_valid_existing_name(list, name);
}

static bool listescape_is_valid_create_name(struct mailbox_list *list,
					    const char *name)
{
	struct listescape_mailbox_list *mlist = LIST_ESCAPE_LIST_CONTEXT(list);

	name = list_escape(mlist, list->ns, name, FALSE);
	return mlist->module_ctx.super.is_valid_create_name(list, name);
}

static void listescape_mail_storage_created(struct mail_storage *storage)
{
	struct listescape_mail_storage *mstorage;
	struct mail_storage_vfuncs *v = storage->vlast;

	mstorage = p_new(storage->pool, struct listescape_mail_storage, 1);
	mstorage->module_ctx.super = *v;
	storage->vlast = &mstorage->module_ctx.super;
	v->mailbox_alloc = listescape_mailbox_alloc;

	MODULE_CONTEXT_SET(storage, listescape_storage_module, mstorage);
}

static void listescape_mailbox_list_created(struct mailbox_list *list)
{
	struct mailbox_list_vfuncs *v = list->vlast;
	struct listescape_mailbox_list *mlist;
	const char *env;

	if (list->hierarchy_sep == list->ns->sep)
		return;

	list->ns->real_sep = list->ns->sep;

	mlist = p_new(list->pool, struct listescape_mailbox_list, 1);
	mlist->module_ctx.super = *v;
	list->vlast = &mlist->module_ctx.super;
	p_array_init(&mlist->iters, list->pool, 4);
	v->iter_init = listescape_mailbox_list_iter_init;
	v->iter_next = listescape_mailbox_list_iter_next;
	v->iter_deinit = listescape_mailbox_list_iter_deinit;
	v->set_subscribed = listescape_set_subscribed;
	v->get_mailbox_name_status = listescape_get_mailbox_name_status;
	v->is_valid_existing_name = listescape_is_valid_existing_name;
	v->is_valid_create_name = listescape_is_valid_create_name;

	env = mail_user_plugin_getenv(list->ns->user, "listescape_char");
	mlist->escape_char = env != NULL && *env != '\0' ?
		env[0] : DEFAULT_ESCAPE_CHAR;

	MODULE_CONTEXT_SET(list, listescape_list_module, mlist);
}

static struct mail_storage_hooks listescape_mail_storage_hooks = {
	.mail_storage_created = listescape_mail_storage_created,
	.mailbox_list_created = listescape_mailbox_list_created
};

void listescape_plugin_init(struct module *module)
{
	mail_storage_hooks_add(module, &listescape_mail_storage_hooks);
}

void listescape_plugin_deinit(void)
{
	mail_storage_hooks_remove(&listescape_mail_storage_hooks);
}
