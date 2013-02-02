/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "mail-storage-hooks.h"
#include "mail-storage-private.h"
#include "mailbox-list-private.h"
#include "mailbox-alias-plugin.h"

#define MAILBOX_ALIAS_USER_CONTEXT(obj) \
	MODULE_CONTEXT(obj, mailbox_alias_user_module)
#define MAILBOX_ALIAS_CONTEXT(obj) \
	MODULE_CONTEXT(obj, mailbox_alias_storage_module)
#define MAILBOX_ALIAS_LIST_CONTEXT(obj) \
	MODULE_CONTEXT(obj, mailbox_alias_mailbox_list_module)

struct mailbox_alias {
	const char *old_vname, *new_vname;
};

struct mailbox_alias_user {
	union mail_user_module_context module_ctx;

	ARRAY(struct mailbox_alias) aliases;
};

struct mailbox_alias_mailbox_list {
	union mailbox_list_module_context module_ctx;
};

struct mailbox_alias_mailbox {
	union mailbox_module_context module_ctx;
};

enum mailbox_symlink_existence {
	MAILBOX_SYMLINK_EXISTENCE_NONEXISTENT,
	MAILBOX_SYMLINK_EXISTENCE_SYMLINK,
	MAILBOX_SYMLINK_EXISTENCE_NOT_SYMLINK
};

static MODULE_CONTEXT_DEFINE_INIT(mailbox_alias_user_module,
				  &mail_user_module_register);
static MODULE_CONTEXT_DEFINE_INIT(mailbox_alias_storage_module,
				  &mail_storage_module_register);
static MODULE_CONTEXT_DEFINE_INIT(mailbox_alias_mailbox_list_module,
				  &mailbox_list_module_register);

const char *mailbox_alias_plugin_version = DOVECOT_ABI_VERSION;

static const char *
mailbox_alias_find_new(struct mail_user *user, const char *new_vname)
{
	struct mailbox_alias_user *auser = MAILBOX_ALIAS_USER_CONTEXT(user);
	const struct mailbox_alias *alias;

	array_foreach(&auser->aliases, alias) {
		if (strcmp(alias->new_vname, new_vname) == 0)
			return alias->old_vname;
	}
	return NULL;
}

static int mailbox_symlink_exists(struct mailbox_list *list, const char *vname,
				  enum mailbox_symlink_existence *existence_r)
{
	struct mailbox_alias_mailbox_list *alist =
		MAILBOX_ALIAS_LIST_CONTEXT(list);
	struct stat st;
	const char *symlink_name, *symlink_path;
	int ret;

	symlink_name = alist->module_ctx.super.get_storage_name(list, vname);
	ret = mailbox_list_get_path(list, symlink_name,
				    MAILBOX_LIST_PATH_TYPE_DIR, &symlink_path);
	if (ret < 0)
		return -1;
	i_assert(ret > 0);

	if (lstat(symlink_path, &st) < 0) {
		if (errno == ENOENT) {
			*existence_r = MAILBOX_SYMLINK_EXISTENCE_NONEXISTENT;
			return 0;
		}
		mailbox_list_set_critical(list,
					  "lstat(%s) failed: %m", symlink_path);
		return -1;
	}
	if (S_ISLNK(st.st_mode))
		*existence_r = MAILBOX_SYMLINK_EXISTENCE_SYMLINK;
	else
		*existence_r = MAILBOX_SYMLINK_EXISTENCE_NOT_SYMLINK;
	return 0;
}

static int mailbox_is_alias_symlink(struct mailbox *box)
{
	enum mailbox_symlink_existence existence;

	if (mailbox_alias_find_new(box->storage->user, box->vname) == NULL)
		return 0;
	if (mailbox_symlink_exists(box->list, box->vname, &existence) < 0) {
		mail_storage_copy_list_error(box->storage, box->list);
		return -1;
	}
	return existence == MAILBOX_SYMLINK_EXISTENCE_SYMLINK ? 1 : 0;
}

static int
mailbox_has_aliases(struct mailbox_list *list, const char *old_vname)
{
	struct mailbox_alias_user *auser =
		MAILBOX_ALIAS_USER_CONTEXT(list->ns->user);
	const struct mailbox_alias *alias;
	enum mailbox_symlink_existence existence;
	int ret = 0;

	array_foreach(&auser->aliases, alias) {
		if (strcmp(alias->old_vname, old_vname) == 0) {
			if (mailbox_symlink_exists(list, alias->new_vname,
						   &existence) < 0)
				ret = -1;
			else if (existence == MAILBOX_SYMLINK_EXISTENCE_SYMLINK)
				return 1;
		}
	}
	return ret;
}

static int
mailbox_alias_create_symlink(struct mailbox *box,
			     const char *old_name, const char *new_name)
{
	const char *old_path, *new_path, *fname;
	int ret;

	ret = mailbox_list_get_path(box->list, old_name,
				    MAILBOX_LIST_PATH_TYPE_DIR, &old_path);
	if (ret > 0) {
		ret = mailbox_list_get_path(box->list, new_name,
					    MAILBOX_LIST_PATH_TYPE_DIR,
					    &new_path);
	}
	if (ret < 0)
		return -1;
	if (ret == 0) {
		mail_storage_set_error(box->storage, MAIL_ERROR_NOTPOSSIBLE,
			"Mailbox aliases not supported by storage");
		return -1;
	}
	fname = strrchr(old_path, '/');
	i_assert(fname != NULL);
	fname++;
	i_assert(strncmp(new_path, old_path, fname-old_path) == 0);

	if (symlink(fname, new_path) < 0) {
		if (errno == EEXIST) {
			mail_storage_set_error(box->storage, MAIL_ERROR_EXISTS,
					       "Mailbox already exists");
			return -1;
		}
		mail_storage_set_critical(box->storage,
			"symlink(%s, %s) failed: %m", fname, new_path);
		return -1;
	}
	return 0;
}

static const char *
mailbox_alias_get_storage_name(struct mailbox_list *list, const char *vname)
{
	struct mailbox_alias_mailbox_list *alist =
		MAILBOX_ALIAS_LIST_CONTEXT(list);
	const char *old_vname;
	enum mailbox_symlink_existence existence;

	/* access the old mailbox so that e.g. full text search won't
	   index the mailbox twice. this also means that deletion must be
	   careful to delete the symlink, box->name. */
	old_vname = mailbox_alias_find_new(list->ns->user, vname);
	if (old_vname != NULL &&
	    mailbox_symlink_exists(list, vname, &existence) == 0 &&
	    existence != MAILBOX_SYMLINK_EXISTENCE_NOT_SYMLINK)
		vname = old_vname;

	return alist->module_ctx.super.get_storage_name(list, vname);
}

static int
mailbox_alias_create(struct mailbox *box, const struct mailbox_update *update,
		     bool directory)
{
	struct mailbox_alias_mailbox *abox = MAILBOX_ALIAS_CONTEXT(box);
	struct mailbox_alias_mailbox_list *alist =
		MAILBOX_ALIAS_LIST_CONTEXT(box->list);
	const char *symlink_name;
	int ret;

	ret = abox->module_ctx.super.create_box(box, update, directory);
	if (mailbox_alias_find_new(box->storage->user, box->vname) == NULL)
		return ret;
	if (ret < 0 && mailbox_get_last_mail_error(box) != MAIL_ERROR_EXISTS)
		return ret;

	/* all the code so far has actually only created the original
	   mailbox. now we'll create the symlink if it's missing. */
	symlink_name = alist->module_ctx.super.
		get_storage_name(box->list, box->vname);
	return mailbox_alias_create_symlink(box, box->name, symlink_name);
}

static int mailbox_alias_delete(struct mailbox *box)
{
	struct mailbox_alias_mailbox *abox = MAILBOX_ALIAS_CONTEXT(box);
	struct mailbox_alias_mailbox_list *alist =
		MAILBOX_ALIAS_LIST_CONTEXT(box->list);
	const char *symlink_name;
	int ret;

	ret = mailbox_has_aliases(box->list, box->vname);
	if (ret < 0)
		return -1;
	if (ret > 0) {
		mail_storage_set_error(box->storage, MAIL_ERROR_NOTPOSSIBLE,
			"Can't delete mailbox while it has aliases");
		return -1;
	}

	if (mailbox_is_alias_symlink(box)) {
		/* we're deleting an alias mailbox. we'll need to handle this
		   explicitly since box->name points to the original mailbox */
		symlink_name = alist->module_ctx.super.
			get_storage_name(box->list, box->vname);
		if (mailbox_list_delete_symlink(box->list, symlink_name) < 0) {
			mail_storage_copy_list_error(box->storage, box->list);
			return -1;
		}
		return 0;
	}

	return abox->module_ctx.super.delete_box(box);
}

static int mailbox_alias_rename(struct mailbox *src, struct mailbox *dest)
{
	struct mailbox_alias_mailbox *abox = MAILBOX_ALIAS_CONTEXT(src);
	int ret;

	if (mailbox_is_alias_symlink(src)) {
		mail_storage_set_error(src->storage, MAIL_ERROR_NOTPOSSIBLE,
				       "Can't rename alias mailboxes");
		return -1;
	}
	if (mailbox_is_alias_symlink(dest)) {
		mail_storage_set_error(src->storage, MAIL_ERROR_NOTPOSSIBLE,
				       "Can't rename to mailbox alias");
		return -1;
	}
	ret = mailbox_has_aliases(src->list, src->vname);
	if (ret < 0)
		return -1;
	if (ret > 0) {
		mail_storage_set_error(src->storage, MAIL_ERROR_NOTPOSSIBLE,
			"Can't rename mailbox while it has aliases");
		return -1;
	}

	return abox->module_ctx.super.rename_box(src, dest);
}

static void mailbox_alias_mail_user_created(struct mail_user *user)
{
	struct mail_user_vfuncs *v = user->vlast;
	struct mailbox_alias_user *auser;
	struct mailbox_alias *alias;
	string_t *oldkey, *newkey;
	const char *old_vname, *new_vname;
	unsigned int i;

	auser = p_new(user->pool, struct mailbox_alias_user, 1);
	auser->module_ctx.super = *v;
	user->vlast = &auser->module_ctx.super;

	p_array_init(&auser->aliases, user->pool, 8);

	oldkey = t_str_new(32);
	newkey = t_str_new(32);
	str_append(oldkey, "mailbox_alias_old");
	str_append(newkey, "mailbox_alias_new");
	for (i = 2;; i++) {
		old_vname = mail_user_plugin_getenv(user, str_c(oldkey));
		new_vname = mail_user_plugin_getenv(user, str_c(newkey));
		if (old_vname == NULL || new_vname == NULL)
			break;

		alias = array_append_space(&auser->aliases);
		alias->old_vname = old_vname;
		alias->new_vname = new_vname;

		str_truncate(oldkey, 0);
		str_truncate(newkey, 0);
		str_printfa(oldkey, "mailbox_alias_old%u", i);
		str_printfa(newkey, "mailbox_alias_new%u", i);
	}

	MODULE_CONTEXT_SET(user, mailbox_alias_user_module, auser);
}

static void mailbox_alias_mailbox_list_created(struct mailbox_list *list)
{
	struct mailbox_list_vfuncs *v = list->vlast;
	struct mailbox_alias_mailbox_list *alist;

	alist = p_new(list->pool, struct mailbox_alias_mailbox_list, 1);
	alist->module_ctx.super = *v;
	list->vlast = &alist->module_ctx.super;

	v->get_storage_name = mailbox_alias_get_storage_name;
	MODULE_CONTEXT_SET(list, mailbox_alias_mailbox_list_module, alist);
}

static void mailbox_alias_mailbox_allocated(struct mailbox *box)
{
	struct mailbox_vfuncs *v = box->vlast;
	struct mailbox_alias_mailbox *abox;

	abox = p_new(box->pool, struct mailbox_alias_mailbox, 1);
	abox->module_ctx.super = *v;
	box->vlast = &abox->module_ctx.super;

	v->create_box = mailbox_alias_create;
	v->delete_box = mailbox_alias_delete;
	v->rename_box = mailbox_alias_rename;
	MODULE_CONTEXT_SET(box, mailbox_alias_storage_module, abox);
}

static struct mail_storage_hooks mailbox_alias_mail_storage_hooks = {
	.mail_user_created = mailbox_alias_mail_user_created,
	.mailbox_list_created = mailbox_alias_mailbox_list_created,
	.mailbox_allocated = mailbox_alias_mailbox_allocated
};

void mailbox_alias_plugin_init(struct module *module)
{
	mail_storage_hooks_add(module, &mailbox_alias_mail_storage_hooks);
}

void mailbox_alias_plugin_deinit(void)
{
	mail_storage_hooks_remove(&mailbox_alias_mail_storage_hooks);
}
