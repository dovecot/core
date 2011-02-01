/* Copyright (c) 2007-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "unichar.h"
#include "imap-match.h"
#include "mailbox-list-private.h"
#include "mail-storage-private.h"
#include "mail-storage-hooks.h"
#include "autocreate-plugin.h"

#include <stdlib.h>

#define AUTOCREATE_USER_CONTEXT(obj) \
	MODULE_CONTEXT(obj, autocreate_user_module)
#define AUTOCREATE_LIST_CONTEXT(obj) \
	MODULE_CONTEXT(obj, autocreate_list_module)
#define AUTOCREATE_CONTEXT(obj) \
	MODULE_CONTEXT(obj, autocreate_storage_module)

enum match_result {
	/* list contains the mailbox */
	MATCH_RESULT_YES	= 0x01,
	/* list contains children of the mailbox */
	MATCH_RESULT_CHILDREN	= 0x02,
	/* list contains parents of the mailbox */
	MATCH_RESULT_PARENT	= 0x04
};

struct autocreate_box {
	const char *name;
	unsigned int name_len;
	enum mailbox_info_flags flags;
	bool child_listed;

	struct mail_namespace *ns;
};
ARRAY_DEFINE_TYPE(autocreate_box, struct autocreate_box);

struct autocreate_user {
	union mail_user_module_context module_ctx;

	ARRAY_TYPE(autocreate_box) autocreate_mailboxes;
	ARRAY_TYPE(autocreate_box) autosubscribe_mailboxes;
};

struct autocreate_mailbox_list_iterate_context {
	union mailbox_list_iterate_module_context module_ctx;

	pool_t pool;
	unsigned int idx;
	struct mailbox_info new_info;
	ARRAY_TYPE(autocreate_box) boxes;
};

struct autocreate_mailbox_list {
	union mailbox_list_module_context module_ctx;
};

const char *autocreate_plugin_version = DOVECOT_VERSION;

static MODULE_CONTEXT_DEFINE_INIT(autocreate_user_module,
				  &mail_user_module_register);
static MODULE_CONTEXT_DEFINE_INIT(autocreate_list_module,
				  &mailbox_list_module_register);
static MODULE_CONTEXT_DEFINE_INIT(autocreate_storage_module,
				  &mail_storage_module_register);

static enum match_result
autocreate_box_match(const ARRAY_TYPE(autocreate_box) *boxes, const char *name,
		     unsigned int *idx_r)
{
	const struct autocreate_box *autoboxes;
	unsigned int i, count, len, name_len = strlen(name);
	enum match_result result = 0;
	char sep;

	*idx_r = -1U;

	autoboxes = array_get(boxes, &count);
	for (i = 0; i < count; i++) {
		len = I_MIN(name_len, autoboxes[i].name_len);
		if (strncmp(name, autoboxes[i].name, len) != 0)
			continue;

		sep = mail_namespace_get_sep(autoboxes[i].ns);
		if (name[len] == '\0' && autoboxes[i].name[len] == '\0') {
			result |= MATCH_RESULT_YES;
			*idx_r = i;
		} else if (name[len] == '\0' && autoboxes[i].name[len] == sep)
			result |= MATCH_RESULT_CHILDREN;
		else if (name[len] == sep && autoboxes[i].name[len] == '\0')
			result |= MATCH_RESULT_PARENT;
	}
	return result;
}

static bool
is_autocreated(struct mail_user *user, const char *name)
{
	struct autocreate_user *auser = AUTOCREATE_USER_CONTEXT(user);
	unsigned int idx;

	return autocreate_box_match(&auser->autocreate_mailboxes,
				    name, &idx) == MATCH_RESULT_YES;
}

static bool
is_autosubscribed(struct mail_user *user, const char *name)
{
	struct autocreate_user *auser = AUTOCREATE_USER_CONTEXT(user);
	unsigned int idx;

	return autocreate_box_match(&auser->autosubscribe_mailboxes,
				    name, &idx) == MATCH_RESULT_YES;
}

static int autocreate_mailbox_open(struct mailbox *box)
{
	union mailbox_module_context *abox = AUTOCREATE_CONTEXT(box);
	int ret;

	if ((ret = abox->super.open(box)) < 0 &&
	    mailbox_get_last_mail_error(box) == MAIL_ERROR_NOTFOUND &&
	    is_autocreated(box->storage->user, box->vname)) {
		/* autocreate the mailbox */
		if (mailbox_create(box, NULL, FALSE) < 0) {
			i_error("autocreate: Failed to create mailbox %s: %s",
				box->vname, mailbox_get_last_error(box, NULL));
		}
		mailbox_close(box);
		ret = box->v.open(box);
	}
	return ret;
}

static int autocreate_mailbox_exists(struct mailbox *box)
{
	union mailbox_module_context *abox = AUTOCREATE_CONTEXT(box);

	if (is_autocreated(box->storage->user, box->vname))
		return 1;

	return abox->super.exists(box);
}

static int
autocreate_mailbox_create(struct mailbox *box,
			  const struct mailbox_update *update,
			  bool directory)
{
	union mailbox_module_context *abox = AUTOCREATE_CONTEXT(box);

	if (abox->super.create(box, update, directory) < 0)
		return -1;

	if (is_autosubscribed(box->storage->user, box->vname)) {
		if (mailbox_set_subscribed(box, TRUE) < 0) {
			i_error("autocreate: Failed to subscribe to mailbox %s: %s",
				box->vname, mailbox_get_last_error(box, NULL));
		}
	}
	return 0;
}

static void autocreate_mailbox_allocated(struct mailbox *box)
{
	struct mailbox_vfuncs *v = box->vlast;
	union mailbox_module_context *abox;

	abox = p_new(box->pool, union mailbox_module_context, 1);
	abox->super = *v;
	box->vlast = &abox->super;
	v->open = autocreate_mailbox_open;
	v->exists = autocreate_mailbox_exists;
	v->create = autocreate_mailbox_create;

	MODULE_CONTEXT_SET_SELF(box, autocreate_storage_module, abox);
}

static struct mailbox_list_iterate_context *
autocreate_iter_init(struct mailbox_list *list,
		     const char *const *patterns,
		     enum mailbox_list_iter_flags flags)
{
	union mailbox_list_module_context *alist =
		AUTOCREATE_LIST_CONTEXT(list);
	struct mail_user *user = list->ns->user;
	struct autocreate_user *auser = AUTOCREATE_USER_CONTEXT(user);
	struct mailbox_list_iterate_context *ctx;
	struct autocreate_mailbox_list_iterate_context *actx;
	const ARRAY_TYPE(autocreate_box) *extra_boxes;
	const struct autocreate_box *autobox;
	pool_t pool;

	ctx = alist->super.iter_init(list, patterns, flags);

	pool = pool_alloconly_create("autocreate list iter", 1024);
	actx = p_new(pool, struct autocreate_mailbox_list_iterate_context, 1);
	actx->pool = pool;

	p_array_init(&actx->boxes, pool, 16);
	if ((flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) == 0)
		extra_boxes = &auser->autocreate_mailboxes;
	else
		extra_boxes = &auser->autosubscribe_mailboxes;

	array_foreach(extra_boxes, autobox) {
		if (autobox->ns == list->ns)
			array_append(&actx->boxes, autobox, 1);
	}

	MODULE_CONTEXT_SET(ctx, autocreate_list_module, actx);
	return ctx;
}

static int autocreate_iter_deinit(struct mailbox_list_iterate_context *ctx)
{
	union mailbox_list_module_context *alist =
		AUTOCREATE_LIST_CONTEXT(ctx->list);
	struct autocreate_mailbox_list_iterate_context *actx =
		AUTOCREATE_LIST_CONTEXT(ctx);

	pool_unref(&actx->pool);
	return alist->super.iter_deinit(ctx);
}

static const struct mailbox_info *
autocreate_iter_existing(struct mailbox_list_iterate_context *ctx)
{
	struct autocreate_mailbox_list_iterate_context *actx =
		AUTOCREATE_LIST_CONTEXT(ctx);
	struct autocreate_user *auser =
		AUTOCREATE_USER_CONTEXT(ctx->list->ns->user);
	struct mailbox_info *info = &actx->new_info;
	enum match_result match, match2;
	unsigned int idx;

	match = autocreate_box_match(&actx->boxes, info->name, &idx);

	if ((match & MATCH_RESULT_YES) != 0) {
		/* we have an exact match in the list.
		   don't list it at the end. */
		array_delete(&actx->boxes, idx, 1);
	}

	if ((match & MATCH_RESULT_CHILDREN) != 0) {
		if ((ctx->flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) != 0)
			info->flags |= MAILBOX_CHILD_SUBSCRIBED;
		else {
			info->flags &= ~MAILBOX_NOCHILDREN;
			info->flags |= MAILBOX_CHILDREN;
		}
	}

	/* make sure the mailbox existence flags are correct. */
	if ((ctx->flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) == 0)
		match2 = match;
	else {
		info->flags |= MAILBOX_SUBSCRIBED;
		match2 = autocreate_box_match(&auser->autocreate_mailboxes,
					      info->name, &idx);
	}
	if ((match2 & MATCH_RESULT_YES) != 0)
		info->flags &= ~MAILBOX_NONEXISTENT;
	if ((match2 & MATCH_RESULT_CHILDREN) != 0) {
		info->flags &= ~MAILBOX_NOCHILDREN;
		info->flags |= MAILBOX_CHILDREN;
	}

	if ((ctx->flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) == 0 &&
	    (ctx->flags & MAILBOX_LIST_ITER_RETURN_SUBSCRIBED) != 0) {
		/* we're listing all mailboxes and want \Subscribed flag */
		match2 = autocreate_box_match(&auser->autosubscribe_mailboxes,
					      info->name, &idx);
		if ((match2 & MATCH_RESULT_YES) != 0) {
			/* mailbox is also marked as autosubscribe */
			info->flags |= MAILBOX_SUBSCRIBED;
		}
		if ((match2 & MATCH_RESULT_CHILDREN) != 0) {
			/* mailbox also has a children marked as
			   autosubscribe */
			info->flags |= MAILBOX_CHILD_SUBSCRIBED;
		}
	}

	if ((match & MATCH_RESULT_PARENT) != 0) {
		/* there are autocreate parent boxes.
		   set their children flag states. */
		struct autocreate_box *autobox;
		char sep;

		array_foreach_modifiable(&actx->boxes, autobox) {
			sep = mail_namespace_get_sep(autobox->ns);

			if (strncmp(info->name, autobox->name,
				    autobox->name_len) != 0 ||
			    info->name[autobox->name_len] != sep)
				continue;

			if ((info->flags & MAILBOX_NONEXISTENT) == 0)
				autobox->flags |= MAILBOX_CHILDREN;
			if ((info->flags & MAILBOX_SUBSCRIBED) != 0)
				autobox->flags |= MAILBOX_CHILD_SUBSCRIBED;
			autobox->child_listed = TRUE;
		}
	}
	return info;
}

static bool autocreate_iter_autobox(struct mailbox_list_iterate_context *ctx,
				    const struct autocreate_box *autobox)
{
	struct autocreate_mailbox_list_iterate_context *actx =
		AUTOCREATE_LIST_CONTEXT(ctx);
	enum match_result match;

	memset(&actx->new_info, 0, sizeof(actx->new_info));
	actx->new_info.ns = ctx->list->ns;
	actx->new_info.name = autobox->name;
	actx->new_info.flags = autobox->flags;

	if ((ctx->flags & MAILBOX_LIST_ITER_SELECT_SUBSCRIBED) != 0)
		actx->new_info.flags |= MAILBOX_SUBSCRIBED;

	if ((actx->new_info.flags & MAILBOX_CHILDREN) == 0)
		actx->new_info.flags |= MAILBOX_NOCHILDREN;

	match = imap_match(ctx->glob, actx->new_info.name);
	if (match == IMAP_MATCH_YES)
		return TRUE;
	if ((match & IMAP_MATCH_PARENT) != 0 && !autobox->child_listed) {
		enum mailbox_info_flags old_flags = actx->new_info.flags;
		char sep = mail_namespace_get_sep(ctx->list->ns);
		const char *p;

		/* e.g. autocreate=foo/bar and we're listing % */
		actx->new_info.flags = MAILBOX_NONEXISTENT |
			(old_flags & (MAILBOX_CHILDREN |
				      MAILBOX_CHILD_SUBSCRIBED));
		if ((old_flags & MAILBOX_NONEXISTENT) == 0) {
			actx->new_info.flags |= MAILBOX_CHILDREN;
			actx->new_info.flags &= ~MAILBOX_NOCHILDREN;
		}
		if ((old_flags & MAILBOX_SUBSCRIBED) != 0)
			actx->new_info.flags |= MAILBOX_CHILD_SUBSCRIBED;
		do {
			p = strrchr(actx->new_info.name, sep);
			i_assert(p != NULL);
			actx->new_info.name =
				t_strdup_until(actx->new_info.name, p);
			match = imap_match(ctx->glob, actx->new_info.name);
		} while (match != IMAP_MATCH_YES);
		return TRUE;
	}
	return FALSE;
}

static const struct mailbox_info *
autocreate_iter_next(struct mailbox_list_iterate_context *ctx)
{
	union mailbox_list_module_context *alist =
		AUTOCREATE_LIST_CONTEXT(ctx->list);
	struct autocreate_mailbox_list_iterate_context *actx =
		AUTOCREATE_LIST_CONTEXT(ctx);
	const struct mailbox_info *info;
	const struct autocreate_box *autoboxes;
	unsigned int count;

	if (actx->idx == 0) {
		info = alist->super.iter_next(ctx);
		if (info != NULL) {
			actx->new_info = *info;
			return autocreate_iter_existing(ctx);
		}
	}

	/* list missing mailboxes */
	autoboxes = array_get(&actx->boxes, &count);
	while (actx->idx < count) {
		if (autocreate_iter_autobox(ctx, &autoboxes[actx->idx++]))
			return &actx->new_info;
	}
	return NULL;
}

static void autocreate_mailbox_list_created(struct mailbox_list *list)
{
	struct mailbox_list_vfuncs *v = list->vlast;
	union mailbox_list_module_context *alist;

	alist = p_new(list->pool, union mailbox_list_module_context, 1);
	alist->super = *v;
	list->vlast = &alist->super;
	v->iter_init = autocreate_iter_init;
	v->iter_deinit = autocreate_iter_deinit;
	v->iter_next = autocreate_iter_next;

	MODULE_CONTEXT_SET_SELF(list, autocreate_list_module, alist);
}

static void
add_autobox(struct mail_user *user, ARRAY_TYPE(autocreate_box) *boxes,
	    const char *value)
{
	struct autocreate_box *autobox;
	struct mail_namespace *ns;

	if (!uni_utf8_str_is_valid(value)) {
		i_error("autocreate: Mailbox name isn't valid UTF-8: %s",
			value);
		return;
	}

	if ((ns = mail_namespace_find(user->namespaces, value)) == NULL) {
		if (user->mail_debug) {
			i_debug("autocreate: Namespace not found for mailbox: %s",
				value);
		}
		return;
	}

	autobox = array_append_space(boxes);
	autobox->name = p_strdup(user->pool, value);
	autobox->name_len = strlen(value);
	autobox->ns = ns;
}

static void read_autobox_settings(struct mail_user *user,
				  ARRAY_TYPE(autocreate_box) *boxes,
				  const char *env_name_base)
{
	const char *value;
	char env_name[20];
	unsigned int i = 1;

	value = mail_user_plugin_getenv(user, env_name_base);
	while (value != NULL) {
		add_autobox(user, boxes, value);

		i_snprintf(env_name, sizeof(env_name), "%s%d",
			   env_name_base, ++i);
		value = mail_user_plugin_getenv(user, env_name);
	}
}

static void
autocreate_mail_namespaces_created(struct mail_namespace *namespaces)
{
	struct mail_user *user = namespaces->user;
	struct autocreate_user *auser;

	auser = p_new(user->pool, struct autocreate_user, 1);
	p_array_init(&auser->autocreate_mailboxes, user->pool, 8);
	read_autobox_settings(user, &auser->autocreate_mailboxes, "autocreate");

	p_array_init(&auser->autosubscribe_mailboxes, user->pool, 8);
	read_autobox_settings(user, &auser->autosubscribe_mailboxes,
			      "autosubscribe");

	MODULE_CONTEXT_SET(user, autocreate_user_module, auser);
}


static struct mail_storage_hooks autocreate_mail_storage_hooks = {
	.mailbox_allocated = autocreate_mailbox_allocated,
	.mailbox_list_created = autocreate_mailbox_list_created,
	.mail_namespaces_created = autocreate_mail_namespaces_created
};

void autocreate_plugin_init(struct module *module)
{
	mail_storage_hooks_add(module, &autocreate_mail_storage_hooks);
}

void autocreate_plugin_deinit(void)
{
	mail_storage_hooks_remove(&autocreate_mail_storage_hooks);
}
