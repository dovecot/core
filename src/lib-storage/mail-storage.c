/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "llist.h"
#include "str.h"
#include "str-sanitize.h"
#include "sha1.h"
#include "unichar.h"
#include "hex-binary.h"
#include "file-dotlock.h"
#include "file-create-locked.h"
#include "istream.h"
#include "eacces-error.h"
#include "mkdir-parents.h"
#include "time-util.h"
#include "var-expand.h"
#include "dsasl-client.h"
#include "imap-date.h"
#include "settings-parser.h"
#include "mail-index-private.h"
#include "mail-index-alloc-cache.h"
#include "mailbox-tree.h"
#include "mailbox-list-private.h"
#include "mail-storage-private.h"
#include "mail-storage-settings.h"
#include "mail-namespace.h"
#include "mail-search.h"
#include "mail-search-register.h"
#include "mail-search-mime-register.h"
#include "mailbox-search-result-private.h"
#include "mailbox-guid-cache.h"
#include "mail-cache.h"

#include <ctype.h>

#define MAILBOX_DELETE_RETRY_SECS 30
#define MAILBOX_MAX_HIERARCHY_NAME_LENGTH 255

extern struct mail_search_register *mail_search_register_imap;
extern struct mail_search_register *mail_search_register_human;

struct event_category event_category_storage = {
	.name = "storage",
};
struct event_category event_category_mailbox = {
	.parent = &event_category_storage,
	.name = "mailbox",
};
struct event_category event_category_mail = {
	.parent = &event_category_mailbox,
	.name = "mail",
};

struct mail_storage_module_register mail_storage_module_register = { 0 };
struct mail_module_register mail_module_register = { 0 };

struct mail_storage_mail_index_module mail_storage_mail_index_module =
	MODULE_CONTEXT_INIT(&mail_index_module_register);
ARRAY_TYPE(mail_storage) mail_storage_classes;

static int mail_storage_init_refcount = 0;

void mail_storage_init(void)
{
	if (mail_storage_init_refcount++ > 0)
		return;
	dsasl_clients_init();
	mailbox_attributes_init();
	mailbox_lists_init();
	mail_storage_hooks_init();
	i_array_init(&mail_storage_classes, 8);
	mail_storage_register_all();
	mailbox_list_register_all();
}

void mail_storage_deinit(void)
{
	i_assert(mail_storage_init_refcount > 0);
	if (--mail_storage_init_refcount > 0)
		return;
	if (mail_search_register_human != NULL)
		mail_search_register_deinit(&mail_search_register_human);
	if (mail_search_register_imap != NULL)
		mail_search_register_deinit(&mail_search_register_imap);
	mail_search_mime_register_deinit();
	if (array_is_created(&mail_storage_classes))
		array_free(&mail_storage_classes);
	mail_storage_hooks_deinit();
	mailbox_lists_deinit();
	mailbox_attributes_deinit();
	dsasl_clients_deinit();
}

void mail_storage_class_register(struct mail_storage *storage_class)
{
	i_assert(mail_storage_find_class(storage_class->name) == NULL);

	/* append it after the list, so the autodetection order is correct */
	array_append(&mail_storage_classes, &storage_class, 1);
}

void mail_storage_class_unregister(struct mail_storage *storage_class)
{
	struct mail_storage *const *classes;
	unsigned int i, count;

	classes = array_get(&mail_storage_classes, &count);
	for (i = 0; i < count; i++) {
		if (classes[i] == storage_class) {
			array_delete(&mail_storage_classes, i, 1);
			break;
		}
	}
}

struct mail_storage *mail_storage_find_class(const char *name)
{
	struct mail_storage *const *classes;
	unsigned int i, count;

	i_assert(name != NULL);

	classes = array_get(&mail_storage_classes, &count);
	for (i = 0; i < count; i++) {
		if (strcasecmp(classes[i]->name, name) == 0)
			return classes[i];
	}
	return NULL;
}

static struct mail_storage *
mail_storage_autodetect(const struct mail_namespace *ns,
			struct mailbox_list_settings *set)
{
	struct mail_storage *const *classes;
	unsigned int i, count;

	classes = array_get(&mail_storage_classes, &count);
	for (i = 0; i < count; i++) {
		if (classes[i]->v.autodetect != NULL) {
			if (classes[i]->v.autodetect(ns, set))
				return classes[i];
		}
	}
	return NULL;
}

static void
mail_storage_set_autodetection(const char **data, const char **driver)
{
	const char *p;

	/* check if data is in driver:data format (eg. mbox:~/mail) */
	p = *data;
	while (i_isalnum(*p) || *p == '_') p++;

	if (*p == ':' && p != *data) {
		/* no autodetection if the storage driver is given. */
		*driver = t_strdup_until(*data, p);
		*data = p + 1;
	}
}

static struct mail_storage *
mail_storage_get_class(struct mail_namespace *ns, const char *driver,
		       struct mailbox_list_settings *list_set,
		       enum mail_storage_flags flags, const char **error_r)
{
	struct mail_storage *storage_class = NULL;
	const char *home;

	if (driver == NULL) {
		/* no mail_location, autodetect */
	} else if (strcmp(driver, "auto") == 0) {
		/* explicit autodetection with "auto" driver. */
		if (list_set->root_dir != NULL &&
		    *list_set->root_dir == '\0') {
			/* handle the same as with driver=NULL */
			list_set->root_dir = NULL;
		}
	} else {
		storage_class = mail_user_get_storage_class(ns->user, driver);
		if (storage_class == NULL) {
			*error_r = t_strdup_printf(
				"Unknown mail storage driver %s", driver);
			return NULL;
		}
	}

	if (list_set->root_dir == NULL || *list_set->root_dir == '\0') {
		/* no root directory given. is this allowed? */
		const struct mailbox_list *list;

		list = list_set->layout == NULL ? NULL :
			mailbox_list_find_class(list_set->layout);
		if (storage_class == NULL &&
		    (flags & MAIL_STORAGE_FLAG_NO_AUTODETECTION) == 0) {
			/* autodetection should take care of this */
		} else if (storage_class != NULL &&
			   (storage_class->class_flags & MAIL_STORAGE_CLASS_FLAG_NO_ROOT) != 0) {
			/* root not required for this storage */
		} else if (list != NULL &&
			   (list->props & MAILBOX_LIST_PROP_NO_ROOT) != 0) {
			/* root not required for this layout */
		} else {
			*error_r = "Root mail directory not given";
			return NULL;
		}
	}

	if (storage_class != NULL) {
		storage_class->v.get_list_settings(ns, list_set);
		return storage_class;
	}

	storage_class = mail_storage_autodetect(ns, list_set);
	if (storage_class != NULL)
		return storage_class;

	(void)mail_user_get_home(ns->user, &home);
	if (home == NULL || *home == '\0') home = "(not set)";

	if (ns->set->location == NULL || *ns->set->location == '\0') {
		*error_r = t_strdup_printf(
			"Mail storage autodetection failed with home=%s", home);
	} else if (str_begins(ns->set->location, "auto:")) {
		*error_r = t_strdup_printf(
			"Autodetection failed for %s (home=%s)",
			ns->set->location, home);
	} else {
		*error_r = t_strdup_printf(
			"Ambiguous mail location setting, "
			"don't know what to do with it: %s "
			"(try prefixing it with mbox: or maildir:)",
			ns->set->location);
	}
	return NULL;
}

static int
mail_storage_verify_root(const char *root_dir, const char *dir_type,
			 const char **error_r)
{
	struct stat st;

	if (stat(root_dir, &st) == 0) {
		/* exists */
		if (S_ISDIR(st.st_mode))
			return 0;
		*error_r = t_strdup_printf(
			"Root mail directory is a file: %s", root_dir);
		return -1;
	} else if (errno == EACCES) {
		*error_r = mail_error_eacces_msg("stat", root_dir);
		return -1;
	} else if (errno != ENOENT) {
		*error_r = t_strdup_printf("stat(%s) failed: %m", root_dir);
		return -1;
	} else {
		*error_r = t_strdup_printf(
			"Root %s directory doesn't exist: %s", dir_type, root_dir);
		return -1;
	}
}

static int
mail_storage_create_root(struct mailbox_list *list,
			 enum mail_storage_flags flags, const char **error_r)
{
	const char *root_dir, *type_name, *error;
	enum mailbox_list_path_type type;

	if (list->set.iter_from_index_dir) {
		type = MAILBOX_LIST_PATH_TYPE_INDEX;
		type_name = "index";
	} else {
		type = MAILBOX_LIST_PATH_TYPE_MAILBOX;
		type_name = "mail";
	}
	if (!mailbox_list_get_root_path(list, type, &root_dir)) {
		/* storage doesn't use directories (e.g. shared root) */
		return 0;
	}

	if ((flags & MAIL_STORAGE_FLAG_NO_AUTOVERIFY) != 0) {
		if (!event_want_debug_log(list->ns->user->event))
			return 0;

		/* we don't need to verify, but since debugging is
		   enabled, check and log if the root doesn't exist */
		if (mail_storage_verify_root(root_dir, type_name, &error) < 0) {
			e_debug(list->ns->user->event,
				"Namespace %s: Creating storage despite: %s",
				list->ns->prefix, error);
		}
		return 0;
	}

	if ((flags & MAIL_STORAGE_FLAG_NO_AUTOCREATE) == 0) {
		/* If the directories don't exist, we'll just autocreate them
		   later. */
		return 0;
	}
	return mail_storage_verify_root(root_dir, type_name, error_r);
}

static bool
mail_storage_match_class(struct mail_storage *storage,
			 const struct mail_storage *storage_class,
			 const struct mailbox_list_settings *set)
{
	if (strcmp(storage->name, storage_class->name) != 0)
		return FALSE;

	if ((storage->class_flags & MAIL_STORAGE_CLASS_FLAG_UNIQUE_ROOT) != 0 &&
	    strcmp(storage->unique_root_dir,
	    	(set->root_dir != NULL ? set->root_dir : "")) != 0)
		return FALSE;

	if (strcmp(storage->name, "shared") == 0) {
		/* allow multiple independent shared namespaces */
		return FALSE;
	}
	return TRUE;
}

static struct mail_storage *
mail_storage_find(struct mail_user *user,
		  const struct mail_storage *storage_class,
		  const struct mailbox_list_settings *set)
{
	struct mail_storage *storage = user->storages;

	for (; storage != NULL; storage = storage->next) {
		if (mail_storage_match_class(storage, storage_class, set))
			return storage;
	}
	return NULL;
}

int mail_storage_create_full(struct mail_namespace *ns, const char *driver,
			     const char *data, enum mail_storage_flags flags,
			     struct mail_storage **storage_r,
			     const char **error_r)
{
	struct mail_storage *storage_class, *storage = NULL;
	struct mailbox_list *list;
	struct mailbox_list_settings list_set;
	enum mailbox_list_flags list_flags = 0;
	const char *p;

	if ((flags & MAIL_STORAGE_FLAG_KEEP_HEADER_MD5) == 0 &&
	    ns->mail_set->pop3_uidl_format != NULL) {
		/* if pop3_uidl_format contains %m, we want to keep the
		   header MD5 sums stored even if we're not running POP3
		   right now. */
		p = ns->mail_set->pop3_uidl_format;
		while ((p = strchr(p, '%')) != NULL) {
			if (p[1] == '%')
				p += 2;
			else if (var_get_key(++p) == 'm') {
				flags |= MAIL_STORAGE_FLAG_KEEP_HEADER_MD5;
				break;
			}
		}
	}

	mailbox_list_settings_init_defaults(&list_set);
	if (data == NULL) {
		/* autodetect */
	} else if (driver != NULL && strcmp(driver, "shared") == 0) {
		/* internal shared namespace */
		list_set.root_dir = ns->user->set->base_dir;
	} else {
		if (driver == NULL)
			mail_storage_set_autodetection(&data, &driver);
		if (mailbox_list_settings_parse(ns->user, data, &list_set,
						error_r) < 0)
			return -1;
	}

	storage_class = mail_storage_get_class(ns, driver, &list_set, flags,
					       error_r);
	if (storage_class == NULL)
		return -1;
	i_assert(list_set.layout != NULL);

	if (ns->list == NULL) {
		/* first storage for namespace */
		if (mail_storage_is_mailbox_file(storage_class))
			list_flags |= MAILBOX_LIST_FLAG_MAILBOX_FILES;
		if ((storage_class->class_flags & MAIL_STORAGE_CLASS_FLAG_NO_ROOT) != 0)
			list_flags |= MAILBOX_LIST_FLAG_NO_MAIL_FILES;
		if ((storage_class->class_flags & MAIL_STORAGE_CLASS_FLAG_NO_LIST_DELETES) != 0)
			list_flags |= MAILBOX_LIST_FLAG_NO_DELETES;
		if (mailbox_list_create(list_set.layout, ns, &list_set,
					list_flags, &list, error_r) < 0) {
			*error_r = t_strdup_printf("Mailbox list driver %s: %s",
						   list_set.layout, *error_r);
			return -1;
		}
		if ((storage_class->class_flags & MAIL_STORAGE_CLASS_FLAG_NO_ROOT) == 0) {
			if (mail_storage_create_root(ns->list, flags, error_r) < 0)
				return -1;
		}
	}

	storage = mail_storage_find(ns->user, storage_class, &list_set);
	if (storage != NULL) {
		/* using an existing storage */
		storage->refcount++;
		mail_namespace_add_storage(ns, storage);
		*storage_r = storage;
		return 0;
	}

	storage = storage_class->v.alloc();
	storage->refcount = 1;
	storage->storage_class = storage_class;
	storage->user = ns->user;
	storage->set = ns->mail_set;
	storage->flags = flags;
	storage->event = event_create(ns->user->event);
	p_array_init(&storage->module_contexts, storage->pool, 5);

	if (storage->v.create != NULL &&
	    storage->v.create(storage, ns, error_r) < 0) {
		*error_r = t_strdup_printf("%s: %s", storage->name, *error_r);
		pool_unref(&storage->pool);
		return -1;
	}

	T_BEGIN {
		hook_mail_storage_created(storage);
	} T_END;

	i_assert(storage->unique_root_dir != NULL ||
		 (storage->class_flags & MAIL_STORAGE_CLASS_FLAG_UNIQUE_ROOT) == 0);
	DLLIST_PREPEND(&ns->user->storages, storage);
	mail_namespace_add_storage(ns, storage);
	*storage_r = storage;
	return 0;
}

int mail_storage_create(struct mail_namespace *ns, const char *driver,
			enum mail_storage_flags flags, const char **error_r)
{
	struct mail_storage *storage;

	return mail_storage_create_full(ns, driver, ns->set->location,
					flags, &storage, error_r);
}

void mail_storage_unref(struct mail_storage **_storage)
{
	struct mail_storage *storage = *_storage;

	i_assert(storage->refcount > 0);

	/* set *_storage=NULL only after calling destroy() callback.
	   for example mdbox wants to access ns->storage */
	if (--storage->refcount > 0) {
		*_storage = NULL;
		return;
	}

	if (storage->mailboxes != NULL) {
		i_panic("Trying to deinit storage without freeing mailbox %s",
			storage->mailboxes->vname);
	}
	if (storage->obj_refcount != 0)
		i_panic("Trying to deinit storage before freeing its objects");

	DLLIST_REMOVE(&storage->user->storages, storage);

	storage->v.destroy(storage);
	i_free(storage->last_internal_error);
	i_free(storage->error_string);
	if (array_is_created(&storage->error_stack)) {
		i_assert(array_count(&storage->error_stack) == 0);
		array_free(&storage->error_stack);
	}
	event_unref(&storage->event);

	*_storage = NULL;
	pool_unref(&storage->pool);

	mail_index_alloc_cache_destroy_unrefed();
}

void mail_storage_obj_ref(struct mail_storage *storage)
{
	i_assert(storage->refcount > 0);

	if (storage->obj_refcount++ == 0)
		mail_user_ref(storage->user);
}

void mail_storage_obj_unref(struct mail_storage *storage)
{
	i_assert(storage->refcount > 0);
	i_assert(storage->obj_refcount > 0);

	if (--storage->obj_refcount == 0) {
		struct mail_user *user = storage->user;
		mail_user_unref(&user);
	}
}

void mail_storage_clear_error(struct mail_storage *storage)
{
	i_free_and_null(storage->error_string);

	i_free(storage->last_internal_error);
	storage->last_error_is_internal = FALSE;
	storage->error = MAIL_ERROR_NONE;
}

void mail_storage_set_error(struct mail_storage *storage,
			    enum mail_error error, const char *string)
{
	if (storage->error_string != string) {
		i_free(storage->error_string);
		storage->error_string = i_strdup(string);
	}
	storage->last_error_is_internal = FALSE;
	storage->error = error;
}

void mail_storage_set_internal_error(struct mail_storage *storage)
{
	const char *str;

	str = t_strflocaltime(MAIL_ERRSTR_CRITICAL_MSG_STAMP, ioloop_time);

	i_free(storage->error_string);
	storage->error_string = i_strdup(str);
	storage->error = MAIL_ERROR_TEMP;

	/* this function doesn't set last_internal_error, so
	   last_error_is_internal can't be TRUE. */
	storage->last_error_is_internal = FALSE;
}

void mail_storage_set_critical(struct mail_storage *storage,
			       const char *fmt, ...)
{
	char *old_error = storage->error_string;
	char *old_internal_error = storage->last_internal_error;
	va_list va;

	storage->error_string = NULL;
	storage->last_internal_error = NULL;
	/* critical errors may contain sensitive data, so let user
	   see only "Internal error" with a timestamp to make it
	   easier to look from log files the actual error message. */
	mail_storage_set_internal_error(storage);

	va_start(va, fmt);
	storage->last_internal_error = i_strdup_vprintf(fmt, va);
	va_end(va);
	storage->last_error_is_internal = TRUE;
	e_error(storage->event, "%s", storage->last_internal_error);

	/* free the old_error and old_internal_error only after the new error
	   is generated, because they may be one of the parameters. */
	i_free(old_error);
	i_free(old_internal_error);
}

void mailbox_set_critical(struct mailbox *box, const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	T_BEGIN {
		mail_storage_set_critical(box->storage, "Mailbox %s: %s",
			box->vname, t_strdup_vprintf(fmt, va));
	} T_END;
	va_end(va);
}

void mail_set_critical(struct mail *mail, const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	T_BEGIN {
		if (mail->saving) {
			mailbox_set_critical(mail->box, "Saving mail: %s",
				t_strdup_vprintf(fmt, va));
		} else {
			mailbox_set_critical(mail->box, "UID=%u: %s",
				mail->uid, t_strdup_vprintf(fmt, va));
		}
	} T_END;
	va_end(va);
}

const char *mail_storage_get_last_internal_error(struct mail_storage *storage,
						 enum mail_error *error_r)
{
	if (error_r != NULL)
		*error_r = storage->error;
	if (storage->last_error_is_internal) {
		i_assert(storage->last_internal_error != NULL);
		return storage->last_internal_error;
	}
	return mail_storage_get_last_error(storage, error_r);
}

const char *mailbox_get_last_internal_error(struct mailbox *box,
					    enum mail_error *error_r)
{
	return mail_storage_get_last_internal_error(mailbox_get_storage(box),
						    error_r);
}

void mail_storage_copy_error(struct mail_storage *dest,
			     struct mail_storage *src)
{
	const char *str;
	enum mail_error error;

	if (src == dest)
		return;

	str = mail_storage_get_last_error(src, &error);
	mail_storage_set_error(dest, error, str);
}

void mail_storage_copy_list_error(struct mail_storage *storage,
				  struct mailbox_list *list)
{
	const char *str;
	enum mail_error error;

	str = mailbox_list_get_last_error(list, &error);
	mail_storage_set_error(storage, error, str);
}

void mailbox_set_index_error(struct mailbox *box)
{
	if (mail_index_is_deleted(box->index)) {
		mailbox_set_deleted(box);
		mail_index_reset_error(box->index);
	} else {
		mail_storage_set_index_error(box->storage, box->index);
	}
}

void mail_storage_set_index_error(struct mail_storage *storage,
				  struct mail_index *index)
{
	const char *index_error;

	mail_storage_set_internal_error(storage);
	/* use the lib-index's error as our internal error string */
	index_error = mail_index_get_error_message(index);
	if (index_error == NULL)
		index_error = "BUG: Unknown internal index error";
	storage->last_internal_error = i_strdup(index_error);
	storage->last_error_is_internal = TRUE;
	mail_index_reset_error(index);
}

const struct mail_storage_settings *
mail_storage_get_settings(struct mail_storage *storage)
{
	return storage->set;
}

struct mail_user *mail_storage_get_user(struct mail_storage *storage)
{
	return storage->user;
}

void mail_storage_set_callbacks(struct mail_storage *storage,
				struct mail_storage_callbacks *callbacks,
				void *context)
{
	storage->callbacks = *callbacks;
	storage->callback_context = context;
}

int mail_storage_purge(struct mail_storage *storage)
{
	return storage->v.purge == NULL ? 0 :
		storage->v.purge(storage);
}

const char *mail_storage_get_last_error(struct mail_storage *storage,
					enum mail_error *error_r)
{
	/* We get here only in error situations, so we have to return some
	   error. If storage->error is NONE, it means we forgot to set it at
	   some point.. */
	if (storage->error == MAIL_ERROR_NONE) {
		if (error_r != NULL)
			*error_r = MAIL_ERROR_TEMP;
		return storage->error_string != NULL ? storage->error_string :
			"BUG: Unknown internal error";
	}

	if (storage->error_string == NULL) {
		/* This shouldn't happen.. */
		storage->error_string =
			i_strdup_printf("BUG: Unknown 0x%x error",
					storage->error);
	}

	if (error_r != NULL)
		*error_r = storage->error;
	return storage->error_string;
}

const char *mailbox_get_last_error(struct mailbox *box,
				   enum mail_error *error_r)
{
	return mail_storage_get_last_error(box->storage, error_r);
}

enum mail_error mailbox_get_last_mail_error(struct mailbox *box)
{
	enum mail_error error;

	mail_storage_get_last_error(box->storage, &error);
	return error;
}

void mail_storage_last_error_push(struct mail_storage *storage)
{
	struct mail_storage_error *err;

	if (!array_is_created(&storage->error_stack))
		i_array_init(&storage->error_stack, 2);
	err = array_append_space(&storage->error_stack);
	err->error_string = i_strdup(storage->error_string);
	err->error = storage->error;
	err->last_error_is_internal = storage->last_error_is_internal;
	if (err->last_error_is_internal)
		err->last_internal_error = i_strdup(storage->last_internal_error);
}

void mail_storage_last_error_pop(struct mail_storage *storage)
{
	unsigned int count = array_count(&storage->error_stack);
	const struct mail_storage_error *err =
		array_idx(&storage->error_stack, count-1);

	i_free(storage->error_string);
	i_free(storage->last_internal_error);
	storage->error_string = err->error_string;
	storage->error = err->error;
	storage->last_error_is_internal = err->last_error_is_internal;
	storage->last_internal_error = err->last_internal_error;
	array_delete(&storage->error_stack, count-1, 1);
}

bool mail_storage_is_mailbox_file(struct mail_storage *storage)
{
	return (storage->class_flags &
		MAIL_STORAGE_CLASS_FLAG_MAILBOX_IS_FILE) != 0;
}

bool mail_storage_set_error_from_errno(struct mail_storage *storage)
{
	const char *error_string;
	enum mail_error error;

	if (!mail_error_from_errno(&error, &error_string))
		return FALSE;
	if (event_want_debug_log(storage->event) && error != MAIL_ERROR_NOTFOUND) {
		/* debugging is enabled - admin may be debugging a
		   (permission) problem, so return FALSE to get the caller to
		   log the full error message. */
		return FALSE;
	}

	mail_storage_set_error(storage, error, error_string);
	return TRUE;
}

const struct mailbox_settings *
mailbox_settings_find(struct mail_namespace *ns, const char *vname)
{
	struct mailbox_settings *const *box_set;

	if (!array_is_created(&ns->set->mailboxes))
		return NULL;

	if (ns->prefix_len > 0 &&
	    strncmp(ns->prefix, vname, ns->prefix_len-1) == 0) {
		if (vname[ns->prefix_len-1] == mail_namespace_get_sep(ns))
			vname += ns->prefix_len;
		else if (vname[ns->prefix_len-1] == '\0') {
			/* namespace prefix itself */
			vname = "";
		}
	}
	array_foreach(&ns->set->mailboxes, box_set) {
		if (strcmp((*box_set)->name, vname) == 0)
			return *box_set;
	}
	return NULL;
}

struct mailbox *mailbox_alloc(struct mailbox_list *list, const char *vname,
			      enum mailbox_flags flags)
{
	struct mailbox_list *new_list = list;
	struct mail_storage *storage;
	struct mailbox *box;
	enum mail_error open_error = 0;
	const char *errstr = NULL;

	i_assert(uni_utf8_str_is_valid(vname));

	if (strncasecmp(vname, "INBOX", 5) == 0 &&
	    !str_begins(vname, "INBOX")) {
		/* make sure INBOX shows up in uppercase everywhere. do this
		   regardless of whether we're in inbox=yes namespace, because
		   clients expect INBOX to be case insensitive regardless of
		   server's internal configuration. */
		if (vname[5] == '\0')
			vname = "INBOX";
		else if (vname[5] != mail_namespace_get_sep(list->ns))
			/* not INBOX prefix */ ;
		else if (strncasecmp(list->ns->prefix, vname, 6) == 0 &&
			 !str_begins(list->ns->prefix, "INBOX")) {
			mailbox_list_set_critical(list,
				"Invalid server configuration: "
				"Namespace prefix=%s must be uppercase INBOX",
				list->ns->prefix);
			open_error = MAIL_ERROR_TEMP;
		} else {
			vname = t_strconcat("INBOX", vname + 5, NULL);
		}
	}

	T_BEGIN {
		if (mailbox_list_get_storage(&new_list, vname, &storage) < 0) {
			/* do a delayed failure at mailbox_open() */
			storage = mail_namespace_get_default_storage(list->ns);
			errstr = mailbox_list_get_last_error(new_list, &open_error);
			errstr = t_strdup(errstr);
		}

		box = storage->v.mailbox_alloc(storage, new_list, vname, flags);
		box->set = mailbox_settings_find(new_list->ns, vname);
		box->open_error = open_error;
		if (open_error != 0)
			mail_storage_set_error(storage, open_error, errstr);
		hook_mailbox_allocated(box);
	} T_END;

	DLLIST_PREPEND(&box->storage->mailboxes, box);
	mail_storage_obj_ref(box->storage);
	return box;
}

struct mailbox *mailbox_alloc_guid(struct mailbox_list *list,
				   const guid_128_t guid,
				   enum mailbox_flags flags)
{
	struct mailbox *box = NULL;
	struct mailbox_metadata metadata;
	enum mail_error open_error = MAIL_ERROR_TEMP;
	const char *vname;

	if (mailbox_guid_cache_find(list, guid, &vname) < 0) {
		vname = NULL;
	} else if (vname != NULL) {
		box = mailbox_alloc(list, vname, flags);
		if (mailbox_get_metadata(box, MAILBOX_METADATA_GUID,
					 &metadata) < 0) {
		} else if (memcmp(metadata.guid, guid,
				  sizeof(metadata.guid)) != 0) {
			/* GUID mismatch, refresh cache and try again */
			mailbox_free(&box);
			mailbox_guid_cache_refresh(list);
			return mailbox_alloc_guid(list, guid, flags);
		} else {
			/* successfully opened the correct mailbox */
			return box;
		}
		i_error("mailbox_alloc_guid(%s): "
			"Couldn't verify mailbox GUID: %s",
			guid_128_to_string(guid),
			mailbox_get_last_internal_error(box, NULL));
		vname = NULL;
		mailbox_free(&box);
	} else {
		vname = t_strdup_printf("(nonexistent mailbox with GUID=%s)",
					guid_128_to_string(guid));
		open_error = MAIL_ERROR_NOTFOUND;
	}

	if (vname == NULL) {
		vname = t_strdup_printf("(error in mailbox with GUID=%s)",
					guid_128_to_string(guid));
	}
	box = mailbox_alloc(list, vname, flags);
	box->open_error = open_error;
	return box;
}

struct mailbox *mailbox_alloc_delivery(struct mail_user *user,
	const char *name, enum mailbox_flags flags)
{
	struct mail_namespace *ns;
	
	flags |= MAILBOX_FLAG_SAVEONLY |
		MAILBOX_FLAG_POST_SESSION;

	ns = mail_namespace_find(user->namespaces, name);
	if (strcmp(name, ns->prefix) == 0 &&
	    (ns->flags & NAMESPACE_FLAG_INBOX_USER) != 0) {
		/* delivering to a namespace prefix means we actually want to
		   deliver to the INBOX instead */
		name = "INBOX";
		ns = mail_namespace_find_inbox(user->namespaces);
	}

	if (strcasecmp(name, "INBOX") == 0) {
		/* deliveries to INBOX must always succeed,
		   regardless of ACLs */
		flags |= MAILBOX_FLAG_IGNORE_ACLS;
	}

	return mailbox_alloc(ns->list, name, flags);
}

void mailbox_set_reason(struct mailbox *box, const char *reason)
{
	i_assert(reason != NULL);

	box->reason = p_strdup(box->pool, reason);
}

bool mailbox_is_autocreated(struct mailbox *box)
{
	if (box->inbox_user)
		return TRUE;
	if ((box->flags & MAILBOX_FLAG_AUTO_CREATE) != 0)
		return TRUE;
	return box->set != NULL &&
		strcmp(box->set->autocreate, MAILBOX_SET_AUTO_NO) != 0;
}

bool mailbox_is_autosubscribed(struct mailbox *box)
{
	if ((box->flags & MAILBOX_FLAG_AUTO_SUBSCRIBE) != 0)
		return TRUE;
	return box->set != NULL &&
		strcmp(box->set->autocreate, MAILBOX_SET_AUTO_SUBSCRIBE) == 0;
}

static int mailbox_autocreate(struct mailbox *box)
{
	const char *errstr;
	enum mail_error error;

	if (mailbox_create(box, NULL, FALSE) < 0) {
		errstr = mailbox_get_last_internal_error(box, &error);
		if (error != MAIL_ERROR_EXISTS) {
			mailbox_set_critical(box,
				"Failed to autocreate mailbox: %s",
				errstr);
			return -1;
		}
	} else if (mailbox_is_autosubscribed(box)) {
		if (mailbox_set_subscribed(box, TRUE) < 0) {
			mailbox_set_critical(box,
				"Failed to autosubscribe to mailbox: %s",
				mailbox_get_last_internal_error(box, NULL));
			return -1;
		}
	}
	return 0;
}

static int mailbox_autocreate_and_reopen(struct mailbox *box)
{
	int ret;

	if (mailbox_autocreate(box) < 0)
		return -1;
	mailbox_close(box);

	ret = box->v.open(box);
	if (ret < 0 && box->inbox_user &&
	    !box->storage->user->inbox_open_error_logged) {
		box->storage->user->inbox_open_error_logged = TRUE;
		mailbox_set_critical(box,
			"Opening INBOX failed: %s",
			mailbox_get_last_internal_error(box, NULL));
	}
	return ret;
}

static bool
mailbox_name_verify_separators(const char *vname, char sep,
			       const char **error_r)
{
	unsigned int i;
	bool prev_sep = FALSE;

	/* Make sure the vname is correct: non-empty, doesn't begin or end
	   with separator and no adjacent separators */
	for (i = 0; vname[i] != '\0'; i++) {
		if (vname[i] == sep) {
			if (prev_sep) {
				*error_r = "Has adjacent hierarchy separators";
				return FALSE;
			}
			prev_sep = TRUE;
		} else {
			prev_sep = FALSE;
		}
	}
	if (prev_sep && i > 0) {
		*error_r = "Ends with hierarchy separator";
		return FALSE;
	}
	return TRUE;
}

static int mailbox_verify_name(struct mailbox *box)
{
	struct mail_namespace *ns = box->list->ns;
	const char *error, *vname = box->vname;
	char list_sep, ns_sep;

	if (box->inbox_user) {
		/* this is INBOX - don't bother with further checks */
		return 0;
	}

	list_sep = mailbox_list_get_hierarchy_sep(box->list);
	ns_sep = mail_namespace_get_sep(ns);

	if (ns->prefix_len > 0) {
		/* vname is either "namespace/box" or "namespace" */
		if (strncmp(vname, ns->prefix, ns->prefix_len-1) != 0 ||
		    (vname[ns->prefix_len-1] != '\0' &&
		     vname[ns->prefix_len-1] != ns->prefix[ns->prefix_len-1])) {
			/* User input shouldn't normally be able to get us in
			   here. The main reason this isn't an assert is to
			   allow any input at all to mailbox_verify_*_name()
			   without crashing. */
			mail_storage_set_error(box->storage, MAIL_ERROR_PARAMS,
				t_strdup_printf("Invalid mailbox name '%s': "
					"Missing namespace prefix '%s'",
					str_sanitize(vname, 80), ns->prefix));
			return -1;
		}
		vname += ns->prefix_len - 1;
		if (vname[0] != '\0') {
			i_assert(vname[0] == ns->prefix[ns->prefix_len-1]);
			vname++;

			if (vname[0] == '\0') {
				/* "namespace/" isn't a valid mailbox name. */
				mail_storage_set_error(box->storage,
						       MAIL_ERROR_PARAMS,
						       "Invalid mailbox name");
				return -1;
			}
		}
	}

	if (ns_sep != list_sep && box->list->set.escape_char == '\0' &&
	    strchr(vname, list_sep) != NULL) {
		mail_storage_set_error(box->storage, MAIL_ERROR_PARAMS, t_strdup_printf(
			"Character not allowed in mailbox name: '%c'", list_sep));
		return -1;
	}
	if (vname[0] == ns_sep &&
	    !box->storage->set->mail_full_filesystem_access) {
		mail_storage_set_error(box->storage, MAIL_ERROR_PARAMS,
			"Invalid mailbox name: Begins with hierarchy separator");
		return -1;
	}

	if (!mailbox_name_verify_separators(vname, ns_sep, &error) ||
	    !mailbox_list_is_valid_name(box->list, box->name, &error)) {
		mail_storage_set_error(box->storage, MAIL_ERROR_PARAMS,
			t_strdup_printf("Invalid mailbox name: %s", error));
		return -1;
	}
	return 0;
}

static int mailbox_verify_existing_name(struct mailbox *box)
{
	const char *path;

	if (box->opened)
		return 0;

	if (mailbox_verify_name(box) < 0)
		return -1;

	/* Make sure box->_path is set, so mailbox_get_path() works from
	   now on. Note that this may also fail with some backends if the
	   mailbox doesn't exist. */
	if (mailbox_get_path_to(box, MAILBOX_LIST_PATH_TYPE_MAILBOX, &path) < 0) {
		if (box->storage->error != MAIL_ERROR_NOTFOUND ||
		    !mailbox_is_autocreated(box))
			return -1;
		/* if this is an autocreated mailbox, create it now */
		if (mailbox_autocreate(box) < 0)
			return -1;
		mailbox_close(box);
		if (mailbox_get_path_to(box, MAILBOX_LIST_PATH_TYPE_MAILBOX,
					&path) < 0)
			return -1;
	}
	return 0;
}

static bool mailbox_name_has_control_chars(const char *name)
{
	const char *p;

	for (p = name; *p != '\0'; p++) {
		if ((unsigned char)*p < ' ')
			return TRUE;
	}
	return FALSE;
}

void mailbox_skip_create_name_restrictions(struct mailbox *box, bool set)
{
	box->skip_create_name_restrictions = set;
}

int mailbox_verify_create_name(struct mailbox *box)
{
	/* mailbox_alloc() already checks that vname is valid UTF8,
	   so we don't need to verify that.

	   check vname instead of storage name, because vname is what is
	   visible to users, while storage name may be a fixed length GUID. */
	if (mailbox_verify_name(box) < 0)
		return -1;
	if (box->skip_create_name_restrictions)
		return 0;
	if (mailbox_name_has_control_chars(box->vname)) {
		mail_storage_set_error(box->storage, MAIL_ERROR_PARAMS,
			"Control characters not allowed in new mailbox names");
		return -1;
	}
	if (strlen(box->vname) > MAILBOX_LIST_NAME_MAX_LENGTH) {
		mail_storage_set_error(box->storage, MAIL_ERROR_PARAMS,
				       "Mailbox name too long");
		return -1;
	}
	/* check individual component names, too */
	const char *old_name = box->name;
	const char *name;
	const char sep = mailbox_list_get_hierarchy_sep(box->list);
	while((name = strchr(old_name, sep)) != NULL) {
		if (name - old_name > MAILBOX_MAX_HIERARCHY_NAME_LENGTH) {
			mail_storage_set_error(box->storage, MAIL_ERROR_PARAMS,
				"Mailbox name too long");
			return -1;
		}
		name++;
		old_name = name;
	}
	if (strlen(old_name) > MAILBOX_MAX_HIERARCHY_NAME_LENGTH) {
		mail_storage_set_error(box->storage, MAIL_ERROR_PARAMS,
				       "Mailbox name too long");
		return -1;
	}
	return 0;
}

static bool have_listable_namespace_prefix(struct mail_namespace *ns,
					   const char *name)
{
	size_t name_len = strlen(name);

	for (; ns != NULL; ns = ns->next) {
		if ((ns->flags & (NAMESPACE_FLAG_LIST_PREFIX |
				  NAMESPACE_FLAG_LIST_CHILDREN)) == 0)
			continue;

		if (ns->prefix_len <= name_len)
			continue;

		/* if prefix has multiple hierarchies, match
		   any of the hierarchies */
		if (strncmp(ns->prefix, name, name_len) == 0 &&
		    ns->prefix[name_len] == mail_namespace_get_sep(ns))
			return TRUE;
	}
	return FALSE;
}

int mailbox_exists(struct mailbox *box, bool auto_boxes,
		   enum mailbox_existence *existence_r)
{
	switch (box->open_error) {
	case 0:
		break;
	case MAIL_ERROR_NOTFOUND:
		*existence_r = MAILBOX_EXISTENCE_NONE;
		return 0;
	default:
		/* unsure if this exists or not */
		return -1;
	}
	if (mailbox_verify_name(box) < 0) {
		/* the mailbox name is invalid. we don't know if it currently
		   exists or not, but since it can never be accessed in any way
		   report it as if it didn't exist. */
		*existence_r = MAILBOX_EXISTENCE_NONE;
		return 0;
	}

	if (auto_boxes && mailbox_is_autocreated(box)) {
		*existence_r = MAILBOX_EXISTENCE_SELECT;
		return 0;
	}

	if (box->v.exists(box, auto_boxes, existence_r) < 0)
		return -1;

	if (!box->inbox_user && *existence_r == MAILBOX_EXISTENCE_NOSELECT &&
	    have_listable_namespace_prefix(box->storage->user->namespaces,
					   box->vname)) {
	       /* listable namespace prefix always exists. */
		*existence_r = MAILBOX_EXISTENCE_NOSELECT;
		return 0;
	}

	/* if this is a shared namespace with only INBOX and
	   mail_shared_explicit_inbox=no, we'll need to mark the namespace as
	   usable here since nothing else will. */
	box->list->ns->flags |= NAMESPACE_FLAG_USABLE;
	return 0;
}

static int ATTR_NULL(2)
mailbox_open_full(struct mailbox *box, struct istream *input)
{
	int ret;

	if (box->opened)
		return 0;

	if (box->reason != NULL) {
		e_debug(box->event,
			"Mailbox opened because: %s",
			box->reason);
	}

	switch (box->open_error) {
	case 0:
		break;
	case MAIL_ERROR_NOTFOUND:
		mail_storage_set_error(box->storage, MAIL_ERROR_NOTFOUND,
			T_MAIL_ERR_MAILBOX_NOT_FOUND(box->vname));
		return -1;
	default:
		mail_storage_set_internal_error(box->storage);
		box->storage->error = box->open_error;
		return -1;
	}

	if (mailbox_verify_existing_name(box) < 0)
		return -1;

	if (input != NULL) {
		if ((box->storage->class_flags &
		     MAIL_STORAGE_CLASS_FLAG_OPEN_STREAMS) == 0) {
			mailbox_set_critical(box,
				"Storage doesn't support streamed mailboxes");
			return -1;
		}
		box->input = input;
		box->flags |= MAILBOX_FLAG_READONLY;
		i_stream_ref(box->input);
	}

	T_BEGIN {
		ret = box->v.open(box);
	} T_END;

	if (ret < 0 && box->storage->error == MAIL_ERROR_NOTFOUND &&
	    !box->deleting && !box->creating &&
	    box->input == NULL && mailbox_is_autocreated(box)) T_BEGIN {
		ret = mailbox_autocreate_and_reopen(box);
	} T_END;

	if (ret < 0) {
		if (box->input != NULL)
			i_stream_unref(&box->input);
		return -1;
	}

	box->list->ns->flags |= NAMESPACE_FLAG_USABLE;
	return 0;
}

static bool mailbox_try_undelete(struct mailbox *box)
{
	time_t mtime;

	i_assert(!box->mailbox_undeleting);

	if ((box->flags & MAILBOX_FLAG_READONLY) != 0) {
		/* most importantly we don't do this because we want to avoid
		   a loop: mdbox storage rebuild -> mailbox_open() ->
		   mailbox_mark_index_deleted() -> mailbox_sync() ->
		   mdbox storage rebuild. */
		return FALSE;
	}
	if (mail_index_get_modification_time(box->index, &mtime) < 0)
		return FALSE;
	if (mtime + MAILBOX_DELETE_RETRY_SECS > time(NULL))
		return FALSE;

	box->mailbox_undeleting = TRUE;
	int ret = mailbox_mark_index_deleted(box, FALSE);
	box->mailbox_undeleting = FALSE;
	if (ret < 0)
		return FALSE;
	box->mailbox_deleted = FALSE;
	return TRUE;
}

int mailbox_open(struct mailbox *box)
{
	/* check that the storage supports stubs if require them */
	if (((box->flags & MAILBOX_FLAG_USE_STUBS) != 0) &&
	    ((box->storage->storage_class->class_flags & MAIL_STORAGE_CLASS_FLAG_STUBS) == 0)) {
		mail_storage_set_error(box->storage, MAIL_ERROR_NOTPOSSIBLE,
				       "Mailbox does not support mail stubs");
		return -1;
	}

	if (mailbox_open_full(box, NULL) < 0) {
		if (!box->mailbox_deleted || box->mailbox_undeleting)
			return -1;

		/* mailbox has been marked as deleted. if this deletion
		   started (and crashed) a long time ago, it can be confusing
		   to user that the mailbox can't be opened. so we'll just
		   undelete it and reopen. */
		if(!mailbox_try_undelete(box))
			return -1;

		/* make sure we close the mailbox in the middle. some backends
		   may not have fully opened the mailbox while it was being
		   undeleted. */
		mailbox_close(box);
		if (mailbox_open_full(box, NULL) < 0)
			return -1;
	}
	return 0;
}

static int mailbox_alloc_index_pvt(struct mailbox *box)
{
	const char *index_dir;
	int ret;

	if (box->index_pvt != NULL)
		return 1;

	ret = mailbox_get_path_to(box, MAILBOX_LIST_PATH_TYPE_INDEX_PRIVATE,
				  &index_dir);
	if (ret <= 0)
		return ret; /* error / no private indexes */

	if (mailbox_create_missing_dir(box, MAILBOX_LIST_PATH_TYPE_INDEX_PRIVATE) < 0)
		return -1;

	box->index_pvt = mail_index_alloc_cache_get(box->storage->event,
		NULL, index_dir, t_strconcat(box->index_prefix, ".pvt", NULL));
	mail_index_set_fsync_mode(box->index_pvt,
				  box->storage->set->parsed_fsync_mode, 0);
	mail_index_set_lock_method(box->index_pvt,
		box->storage->set->parsed_lock_method,
		mail_storage_get_lock_timeout(box->storage, UINT_MAX));
	return 1;
}

int mailbox_open_index_pvt(struct mailbox *box)
{
	enum mail_index_open_flags index_flags;
	int ret;

	if (box->view_pvt != NULL)
		return 1;
	if (mailbox_get_private_flags_mask(box) == 0)
		return 0;

	if ((ret = mailbox_alloc_index_pvt(box)) <= 0)
		return ret;
	index_flags = MAIL_INDEX_OPEN_FLAG_CREATE |
		mail_storage_settings_to_index_flags(box->storage->set);
	if ((box->flags & MAILBOX_FLAG_SAVEONLY) != 0)
		index_flags |= MAIL_INDEX_OPEN_FLAG_SAVEONLY;
	if (mail_index_open(box->index_pvt, index_flags) < 0)
		return -1;
	box->view_pvt = mail_index_view_open(box->index_pvt);
	return 1;
}

int mailbox_open_stream(struct mailbox *box, struct istream *input)
{
	return mailbox_open_full(box, input);
}

int mailbox_enable(struct mailbox *box, enum mailbox_feature features)
{
	if (mailbox_verify_name(box) < 0)
		return -1;
	return box->v.enable(box, features);
}

enum mailbox_feature mailbox_get_enabled_features(struct mailbox *box)
{
	return box->enabled_features;
}

void mail_storage_free_binary_cache(struct mail_storage *storage)
{
	if (storage->binary_cache.box == NULL)
		return;

	timeout_remove(&storage->binary_cache.to);
	i_stream_destroy(&storage->binary_cache.input);
	i_zero(&storage->binary_cache);
}

void mailbox_close(struct mailbox *box)
{
	if (!box->opened)
		return;

	if (box->transaction_count != 0) {
		i_panic("Trying to close mailbox %s with open transactions",
			box->name);
	}
	box->v.close(box);

	if (box->storage->binary_cache.box == box)
		mail_storage_free_binary_cache(box->storage);
	box->opened = FALSE;
	box->mailbox_deleted = FALSE;
	array_clear(&box->search_results);

	if (array_is_created(&box->recent_flags))
		array_free(&box->recent_flags);
	box->recent_flags_prev_uid = 0;
	box->recent_flags_count = 0;
}

void mailbox_free(struct mailbox **_box)
{
	struct mailbox *box = *_box;

	*_box = NULL;

	mailbox_close(box);
	box->v.free(box);

	if (box->attribute_iter_count != 0) {
		i_panic("Trying to free mailbox %s with %u open attribute iterators",
			box->name, box->attribute_iter_count);
	}

	DLLIST_REMOVE(&box->storage->mailboxes, box);
	mail_storage_obj_unref(box->storage);
	pool_unref(&box->metadata_pool);
	pool_unref(&box->pool);
}

bool mailbox_equals(const struct mailbox *box1,
		    const struct mail_namespace *ns2, const char *vname2)
{
	struct mail_namespace *ns1 = mailbox_get_namespace(box1);
	const char *name1;

	if (ns1 != ns2)
		return FALSE;

        name1 = mailbox_get_vname(box1);
	if (strcmp(name1, vname2) == 0)
		return TRUE;

	return strcasecmp(name1, "INBOX") == 0 &&
		strcasecmp(vname2, "INBOX") == 0;
}

bool mailbox_is_any_inbox(struct mailbox *box)
{
	return box->inbox_any;
}

static void mailbox_copy_cache_decisions_from_inbox(struct mailbox *box)
{
	struct mail_namespace *ns =
		mail_namespace_find_inbox(box->storage->user->namespaces);
	struct mailbox *inbox =
		mailbox_alloc(ns->list, "INBOX", MAILBOX_FLAG_READONLY);
	enum mailbox_existence existence;

	/* this should be NoSelect but since inbox can never be
	   NoSelect we use EXISTENCE_NONE to avoid creating inbox by accident */
	mailbox_set_reason(inbox, "copy caching decisions");
	if (mailbox_exists(inbox, FALSE, &existence) == 0 &&
	    existence != MAILBOX_EXISTENCE_NONE &&
	    mailbox_open(inbox) == 0 &&
	    mailbox_open(box) == 0) {
		struct mail_index_transaction *dit =
			mail_index_transaction_begin(box->view,
						     MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL);

		mail_cache_decisions_copy(dit, inbox->cache, box->cache);

		/* we can't do much about errors here */
		(void)mail_index_transaction_commit(&dit);
	}

	mailbox_free(&inbox);
}

int mailbox_create(struct mailbox *box, const struct mailbox_update *update,
		   bool directory)
{
	int ret;

	if (mailbox_verify_create_name(box) < 0)
		return -1;

	/* Avoid race conditions by keeping mailbox list locked during changes.
	   This especially fixes a race during INBOX creation with LAYOUT=index
	   because it scans for missing mailboxes if INBOX doesn't exist. The
	   second process's scan can find a half-created INBOX and add it,
	   causing the first process to become confused. */
	if (mailbox_list_lock(box->list) < 0) {
		mail_storage_copy_list_error(box->storage, box->list);
		return -1;
	}
	box->creating = TRUE;
	ret = box->v.create_box(box, update, directory);
	box->creating = FALSE;
	mailbox_list_unlock(box->list);

	if (ret == 0) {
		box->list->guid_cache_updated = TRUE;
		if (!box->inbox_any)
			mailbox_copy_cache_decisions_from_inbox(box);
	} else if (box->opened) {
		/* Creation failed after (partially) opening the mailbox.
		   It may not be in a valid state, so close it. */
		mail_storage_last_error_push(box->storage);
		mailbox_close(box);
		mail_storage_last_error_pop(box->storage);
	}
	return ret;
}

int mailbox_update(struct mailbox *box, const struct mailbox_update *update)
{
	int ret;

	i_assert(update->min_next_uid == 0 ||
		 update->min_first_recent_uid == 0 ||
		 update->min_first_recent_uid <= update->min_next_uid);

	if (mailbox_verify_existing_name(box) < 0)
		return -1;
	ret = box->v.update_box(box, update);
	if (!guid_128_is_empty(update->mailbox_guid))
		box->list->guid_cache_invalidated = TRUE;
	return ret;
}

int mailbox_mark_index_deleted(struct mailbox *box, bool del)
{
	struct mail_index_transaction *trans;
	enum mail_index_transaction_flags trans_flags = 0;
	enum mailbox_flags old_flag;
	int ret;

	if (box->marked_deleted && del) {
		/* we already marked it deleted. this allows plugins to
		   "lock" the deletion earlier. */
		return 0;
	}

	old_flag = box->flags & MAILBOX_FLAG_OPEN_DELETED;
	box->flags |= MAILBOX_FLAG_OPEN_DELETED;
	ret = mailbox_open(box);
	box->flags = (box->flags & ~MAILBOX_FLAG_OPEN_DELETED) | old_flag;
	if (ret < 0)
		return -1;

	trans_flags = del ? 0 : MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL;
	trans = mail_index_transaction_begin(box->view, trans_flags);
	if (del)
		mail_index_set_deleted(trans);
	else
		mail_index_set_undeleted(trans);
	if (mail_index_transaction_commit(&trans) < 0) {
		mailbox_set_index_error(box);
		return -1;
	}

	if (del) {
		/* sync the mailbox. this finishes the index deletion and it
		   can succeed only for a single session. we do it here, so the
		   rest of the deletion code doesn't have to worry about race
		   conditions. */
		box->delete_sync_check = TRUE;
		ret = mailbox_sync(box, MAILBOX_SYNC_FLAG_FULL_READ);
		box->delete_sync_check = FALSE;
		if (ret < 0)
			return -1;
	}

	box->marked_deleted = del;
	return 0;
}

static void mailbox_close_reset_path(struct mailbox *box)
{
	i_zero(&box->_perm);
	box->_path = NULL;
	box->_index_path = NULL;
}

int mailbox_delete(struct mailbox *box)
{
	bool list_locked;
	int ret;

	if (*box->name == '\0') {
		mail_storage_set_error(box->storage, MAIL_ERROR_PARAMS,
				       "Storage root can't be deleted");
		return -1;
	}

	box->deleting = TRUE;
	if (mailbox_open(box) < 0) {
		if (mailbox_get_last_mail_error(box) != MAIL_ERROR_NOTFOUND &&
		    !box->mailbox_deleted)
			return -1;
		/* might be a \noselect mailbox, so continue deletion */
	}

	if (mailbox_list_lock(box->list) < 0) {
		mail_storage_copy_list_error(box->storage, box->list);
		list_locked = FALSE;
		ret = -1;
	} else {
		list_locked = TRUE;
		ret = box->v.delete_box(box);
	}
	if (ret < 0 && box->marked_deleted) {
		/* deletion failed. revert the mark so it can maybe be
		   tried again later. */
		if (mailbox_mark_index_deleted(box, FALSE) < 0)
			ret = -1;
	}
	if (list_locked)
		mailbox_list_unlock(box->list);

	box->deleting = FALSE;
	mailbox_close(box);

	/* if mailbox is reopened, its path may be different with
	   LAYOUT=index */
	mailbox_close_reset_path(box);
	return ret;
}

int mailbox_delete_empty(struct mailbox *box)
{
	int ret;

	/* FIXME: should be a parameter to delete(), but since it changes API
	   don't do it for now */
	box->deleting_must_be_empty = TRUE;
	ret = mailbox_delete(box);
	box->deleting_must_be_empty = FALSE;
	return ret;
}

static bool
mail_storages_rename_compatible(struct mail_storage *storage1,
				struct mail_storage *storage2,
				const char **error_r)
{
	if (storage1 == storage2)
		return TRUE;

	if (strcmp(storage1->name, storage2->name) != 0) {
		*error_r = t_strdup_printf("storage %s != %s",
					   storage1->name, storage2->name);
		return FALSE;
	}
	if ((storage1->class_flags & MAIL_STORAGE_CLASS_FLAG_UNIQUE_ROOT) != 0) {
		/* e.g. mdbox where all mails are in storage/ directory and
		   they can't be easily moved from there. */
		*error_r = t_strdup_printf("storage %s uses unique root",
					   storage1->name);
		return FALSE;
	}
	return TRUE;
}

static bool nullequals(const void *p1, const void *p2)
{
	return (p1 == NULL && p2 == NULL) || (p1 != NULL && p2 != NULL);
}

static bool
mailbox_lists_rename_compatible(struct mailbox_list *list1,
				struct mailbox_list *list2,
				const char **error_r)
{
	if (!nullequals(list1->set.alt_dir, list2->set.alt_dir)) {
		*error_r = t_strdup_printf("Namespace %s has alt dir, %s doesn't",
					   list1->ns->prefix, list2->ns->prefix);
		return FALSE;
	}
	if (!nullequals(list1->set.index_dir, list2->set.index_dir)) {
		*error_r = t_strdup_printf("Namespace %s has index dir, %s doesn't",
					   list1->ns->prefix, list2->ns->prefix);
		return FALSE;
	}
	if (!nullequals(list1->set.index_cache_dir, list2->set.index_cache_dir)) {
		*error_r = t_strdup_printf("Namespace %s has index cache dir, %s doesn't",
					   list1->ns->prefix, list2->ns->prefix);
		return FALSE;
	}
	if (!nullequals(list1->set.control_dir, list2->set.control_dir)) {
		*error_r = t_strdup_printf("Namespace %s has control dir, %s doesn't",
					   list1->ns->prefix, list2->ns->prefix);
		return FALSE;
	}
	return TRUE;
}

static
int mailbox_rename_check_children(struct mailbox *src, struct mailbox *dest)
{
	int ret = 0;
	size_t src_prefix_len = strlen(src->vname)+1; /* include separator */
	size_t dest_prefix_len = strlen(dest->vname)+1;
	/* this can return folders with * in their name, that are not
	   actually our children */
	char ns_sep = mail_namespace_get_sep(src->list->ns);
	const char *pattern = t_strdup_printf("%s%c*", src->vname, ns_sep);

	struct mailbox_list_iterate_context *iter = mailbox_list_iter_init(src->list, pattern,
				      MAILBOX_LIST_ITER_RETURN_NO_FLAGS);

	const struct mailbox_info *child;
	while((child = mailbox_list_iter_next(iter)) != NULL) {
		if (strncmp(child->vname, src->vname, src_prefix_len-1) != 0 ||
		    child->vname[src_prefix_len-1] != ns_sep)
			continue; /* not our child */
		/* if total length of new name exceeds the limit, fail */
		if (strlen(child->vname + src_prefix_len)+dest_prefix_len > MAILBOX_LIST_NAME_MAX_LENGTH) {
			mail_storage_set_error(src->storage, MAIL_ERROR_PARAMS,
				"Mailbox or child name too long");
			ret = -1;
			break;
		}
	}

	/* something went bad */
	if (mailbox_list_iter_deinit(&iter) < 0) {
		mail_storage_copy_list_error(src->storage, src->list);
		ret = -1;
	}
	return ret;
}

int mailbox_rename(struct mailbox *src, struct mailbox *dest)
{
	const char *error = NULL;

	/* Check only name validity, \Noselect don't necessarily exist. */
	if (mailbox_verify_name(src) < 0)
		return -1;
	if (*src->name == '\0') {
		mail_storage_set_error(src->storage, MAIL_ERROR_PARAMS,
				       "Can't rename mailbox root");
		return -1;
	}
	if (mailbox_verify_create_name(dest) < 0) {
		mail_storage_copy_error(src->storage, dest->storage);
		return -1;
	}
	if (mailbox_rename_check_children(src, dest) != 0) {
		return -1;
	}

	if (!mail_storages_rename_compatible(src->storage,
					     dest->storage, &error) ||
	    !mailbox_lists_rename_compatible(src->list,
					     dest->list, &error)) {
		e_debug(src->event,
			"Can't rename '%s' to '%s': %s",
			src->vname, dest->vname, error);
		mail_storage_set_error(src->storage, MAIL_ERROR_NOTPOSSIBLE,
			"Can't rename mailboxes across specified storages.");
		return -1;
	}
	if (src->list != dest->list &&
	    (src->list->ns->type != MAIL_NAMESPACE_TYPE_PRIVATE ||
	     dest->list->ns->type != MAIL_NAMESPACE_TYPE_PRIVATE)) {
		mail_storage_set_error(src->storage, MAIL_ERROR_NOTPOSSIBLE,
			"Renaming not supported across non-private namespaces.");
		return -1;
	}
	if (src->list == dest->list && strcmp(src->name, dest->name) == 0) {
		mail_storage_set_error(src->storage, MAIL_ERROR_EXISTS,
				       "Can't rename mailbox to itself.");
		return -1;
	}

	/* It would be safer to lock both source and destination, but that
	   could lead to deadlocks. So at least for now lets just lock only the
	   destination list. */
	if (mailbox_list_lock(dest->list) < 0) {
		mail_storage_copy_list_error(src->storage, dest->list);
		return -1;
	}
	int ret = src->v.rename_box(src, dest);
	mailbox_list_unlock(dest->list);
	if (ret < 0)
		return -1;
	src->list->guid_cache_invalidated = TRUE;
	dest->list->guid_cache_invalidated = TRUE;
	return 0;
}

int mailbox_set_subscribed(struct mailbox *box, bool set)
{
	if (mailbox_verify_name(box) < 0)
		return -1;
	if (mailbox_list_iter_subscriptions_refresh(box->list) < 0) {
		mail_storage_copy_list_error(box->storage, box->list);
		return -1;
	}
	if (mailbox_is_subscribed(box) == set)
		return 0;
	return box->v.set_subscribed(box, set);
}

bool mailbox_is_subscribed(struct mailbox *box)
{
	struct mailbox_node *node;

	i_assert(box->list->subscriptions != NULL);

	node = mailbox_tree_lookup(box->list->subscriptions, box->vname);
	return node != NULL && (node->flags & MAILBOX_SUBSCRIBED) != 0;
}

struct mail_storage *mailbox_get_storage(const struct mailbox *box)
{
	return box->storage;
}

struct mail_namespace *
mailbox_get_namespace(const struct mailbox *box)
{
	return box->list->ns;
}

const struct mail_storage_settings *mailbox_get_settings(struct mailbox *box)
{
	return box->storage->set;
}

const char *mailbox_get_name(const struct mailbox *box)
{
	return box->name;
}

const char *mailbox_get_vname(const struct mailbox *box)
{
	return box->vname;
}

bool mailbox_is_readonly(struct mailbox *box)
{
	i_assert(box->opened);

	return box->v.is_readonly(box);
}

bool mailbox_backends_equal(const struct mailbox *box1,
			    const struct mailbox *box2)
{
	struct mail_namespace *ns1 = box1->list->ns, *ns2 = box2->list->ns;

	if (strcmp(box1->name, box2->name) != 0)
		return FALSE;

	while (ns1->alias_for != NULL)
		ns1 = ns1->alias_for;
	while (ns2->alias_for != NULL)
		ns2 = ns2->alias_for;
	return ns1 == ns2;
}

static void
mailbox_get_status_set_defaults(struct mailbox *box,
				struct mailbox_status *status_r)
{
	i_zero(status_r);
	if ((box->storage->class_flags & MAIL_STORAGE_CLASS_FLAG_HAVE_MAIL_GUIDS) != 0)
		status_r->have_guids = TRUE;
	if ((box->storage->class_flags & MAIL_STORAGE_CLASS_FLAG_HAVE_MAIL_SAVE_GUIDS) != 0)
		status_r->have_save_guids = TRUE;
	if ((box->storage->class_flags & MAIL_STORAGE_CLASS_FLAG_HAVE_MAIL_GUID128) != 0)
		status_r->have_only_guid128 = TRUE;
}

int mailbox_get_status(struct mailbox *box,
		       enum mailbox_status_items items,
		       struct mailbox_status *status_r)
{
	mailbox_get_status_set_defaults(box, status_r);
	if (mailbox_verify_existing_name(box) < 0)
		return -1;

	if (box->v.get_status(box, items, status_r) < 0)
		return -1;
	i_assert(status_r->have_guids || !status_r->have_save_guids);
	return 0;
}

void mailbox_get_open_status(struct mailbox *box,
			     enum mailbox_status_items items,
			     struct mailbox_status *status_r)
{
	i_assert(box->opened);
	i_assert((items & MAILBOX_STATUS_FAILING_ITEMS) == 0);

	mailbox_get_status_set_defaults(box, status_r);
	if (box->v.get_status(box, items, status_r) < 0)
		i_unreached();
}

int mailbox_get_metadata(struct mailbox *box, enum mailbox_metadata_items items,
			 struct mailbox_metadata *metadata_r)
{
	i_zero(metadata_r);
	if (mailbox_verify_existing_name(box) < 0)
		return -1;

	if (box->metadata_pool != NULL)
		p_clear(box->metadata_pool);

	if (box->v.get_metadata(box, items, metadata_r) < 0)
		return -1;

	i_assert((items & MAILBOX_METADATA_GUID) == 0 ||
		 !guid_128_is_empty(metadata_r->guid));
	return 0;
}

enum mail_flags mailbox_get_private_flags_mask(struct mailbox *box)
{
	if (box->v.get_private_flags_mask != NULL)
		return box->v.get_private_flags_mask(box);
	else if (box->list->set.index_pvt_dir != NULL)
		return MAIL_SEEN; /* FIXME */
	else
		return 0;
}

struct mailbox_sync_context *
mailbox_sync_init(struct mailbox *box, enum mailbox_sync_flags flags)
{
	struct mailbox_sync_context *ctx;

	if (box->transaction_count != 0) {
		i_panic("Trying to sync mailbox %s with open transactions",
			box->name);
	}
	if (!box->opened) {
		if (mailbox_open(box) < 0) {
			ctx = i_new(struct mailbox_sync_context, 1);
			ctx->box = box;
			ctx->flags = flags;
			ctx->open_failed = TRUE;
			return ctx;
		}
	}
	T_BEGIN {
		ctx = box->v.sync_init(box, flags);
	} T_END;
	return ctx;
}

bool mailbox_sync_next(struct mailbox_sync_context *ctx,
		       struct mailbox_sync_rec *sync_rec_r)
{
	if (ctx->open_failed)
		return FALSE;
	return ctx->box->v.sync_next(ctx, sync_rec_r);
}

int mailbox_sync_deinit(struct mailbox_sync_context **_ctx,
			struct mailbox_sync_status *status_r)
{
	struct mailbox_sync_context *ctx = *_ctx;
	struct mailbox *box = ctx->box;
	const char *errormsg;
	enum mail_error error;
	int ret;

	*_ctx = NULL;

	i_zero(status_r);

	if (!ctx->open_failed)
		ret = box->v.sync_deinit(ctx, status_r);
	else {
		i_free(ctx);
		ret = -1;
	}
	if (ret < 0 && box->inbox_user &&
	    !box->storage->user->inbox_open_error_logged) {
		errormsg = mailbox_get_last_internal_error(box, &error);
		if (error == MAIL_ERROR_NOTPOSSIBLE) {
			box->storage->user->inbox_open_error_logged = TRUE;
			i_error("Syncing INBOX failed: %s", errormsg);
		}
	}
	if (ret == 0)
		box->synced = TRUE;
	return ret;
}

int mailbox_sync(struct mailbox *box, enum mailbox_sync_flags flags)
{
	struct mailbox_sync_context *ctx;
	struct mailbox_sync_status status;

	if (array_count(&box->search_results) == 0) {
		/* we don't care about mailbox's current state, so we might
		   as well fix inconsistency state */
		flags |= MAILBOX_SYNC_FLAG_FIX_INCONSISTENT;
	}

	ctx = mailbox_sync_init(box, flags);
	return mailbox_sync_deinit(&ctx, &status);
}

#undef mailbox_notify_changes
void mailbox_notify_changes(struct mailbox *box,
			    mailbox_notify_callback_t *callback, void *context)
{
	i_assert(box->opened);

	box->notify_callback = callback;
	box->notify_context = context;

	box->v.notify_changes(box);
}

void mailbox_notify_changes_stop(struct mailbox *box)
{
	i_assert(box->opened);

	box->notify_callback = NULL;
	box->notify_context = NULL;

	box->v.notify_changes(box);
}

struct mail_search_context *
mailbox_search_init(struct mailbox_transaction_context *t,
		    struct mail_search_args *args,
		    const enum mail_sort_type *sort_program,
		    enum mail_fetch_field wanted_fields,
		    struct mailbox_header_lookup_ctx *wanted_headers)
{
	i_assert(wanted_headers == NULL || wanted_headers->box == t->box);

	mail_search_args_ref(args);
	if (!args->simplified)
		mail_search_args_simplify(args);
	return t->box->v.search_init(t, args, sort_program,
				     wanted_fields, wanted_headers);
}

int mailbox_search_deinit(struct mail_search_context **_ctx)
{
	struct mail_search_context *ctx = *_ctx;
	struct mail_search_args *args = ctx->args;
	int ret;

	*_ctx = NULL;
	mailbox_search_results_initial_done(ctx);
	ret = ctx->transaction->box->v.search_deinit(ctx);
	mail_search_args_unref(&args);
	return ret;
}

bool mailbox_search_next(struct mail_search_context *ctx, struct mail **mail_r)
{
	bool tryagain;

	while (!mailbox_search_next_nonblock(ctx, mail_r, &tryagain)) {
		if (!tryagain)
			return FALSE;
	}
	return TRUE;
}

bool mailbox_search_next_nonblock(struct mail_search_context *ctx,
				  struct mail **mail_r, bool *tryagain_r)
{
	struct mailbox *box = ctx->transaction->box;

	*mail_r = NULL;
	*tryagain_r = FALSE;

	if (!box->v.search_next_nonblock(ctx, mail_r, tryagain_r))
		return FALSE;
	else {
		mailbox_search_results_add(ctx, (*mail_r)->uid);
		return TRUE;
	}
}

bool mailbox_search_seen_lost_data(struct mail_search_context *ctx)
{
	return ctx->seen_lost_data;
}

int mailbox_search_result_build(struct mailbox_transaction_context *t,
				struct mail_search_args *args,
				enum mailbox_search_result_flags flags,
				struct mail_search_result **result_r)
{
	struct mail_search_context *ctx;
	struct mail *mail;
	int ret;

	ctx = mailbox_search_init(t, args, NULL, 0, NULL);
	*result_r = mailbox_search_result_save(ctx, flags);
	while (mailbox_search_next(ctx, &mail)) ;

	ret = mailbox_search_deinit(&ctx);
	if (ret < 0)
		mailbox_search_result_free(result_r);
	return ret;
}

struct mailbox_transaction_context *
mailbox_transaction_begin(struct mailbox *box,
			  enum mailbox_transaction_flags flags,
			  const char *reason)
{
	struct mailbox_transaction_context *trans;

	i_assert((flags & MAILBOX_TRANSACTION_FLAG_FILL_IN_STUB) == 0 ||
		 (box->flags & MAILBOX_FLAG_USE_STUBS) != 0);

	i_assert(box->opened);

	box->transaction_count++;
	trans = box->v.transaction_begin(box, flags, reason);
	i_assert(trans->reason != NULL);
	return trans;
}

int mailbox_transaction_commit(struct mailbox_transaction_context **t)
{
	struct mail_transaction_commit_changes changes;
	int ret;

	/* Store changes temporarily so that plugins overriding
	   transaction_commit() can look at them. */
	ret = mailbox_transaction_commit_get_changes(t, &changes);
	pool_unref(&changes.pool);
	return ret;
}

int mailbox_transaction_commit_get_changes(
	struct mailbox_transaction_context **_t,
	struct mail_transaction_commit_changes *changes_r)
{
	struct mailbox_transaction_context *t = *_t;
	struct mailbox *box = t->box;
	unsigned int save_count = t->save_count;
	int ret;

	changes_r->pool = NULL;

	*_t = NULL;
	T_BEGIN {
		ret = box->v.transaction_commit(t, changes_r);
	} T_END;
	/* either all the saved messages get UIDs or none, because a) we
	   failed, b) MAILBOX_TRANSACTION_FLAG_ASSIGN_UIDS not set,
	   c) backend doesn't support it (e.g. virtual plugin) */
	i_assert(ret < 0 ||
		 seq_range_count(&changes_r->saved_uids) == save_count ||
		 array_count(&changes_r->saved_uids) == 0);
	/* decrease the transaction count only after transaction_commit().
	   that way if it creates and destroys transactions internally, we
	   don't see transaction_count=0 until the parent transaction is fully
	   finished */
	box->transaction_count--;
	if (ret < 0 && changes_r->pool != NULL)
		pool_unref(&changes_r->pool);
	return ret;
}

void mailbox_transaction_rollback(struct mailbox_transaction_context **_t)
{
	struct mailbox_transaction_context *t = *_t;
	struct mailbox *box = t->box;

	*_t = NULL;
	box->v.transaction_rollback(t);
	box->transaction_count--;
}

unsigned int mailbox_transaction_get_count(const struct mailbox *box)
{
	return box->transaction_count;
}

void mailbox_transaction_set_max_modseq(struct mailbox_transaction_context *t,
					uint64_t max_modseq,
					ARRAY_TYPE(seq_range) *seqs)
{
	mail_index_transaction_set_max_modseq(t->itrans, max_modseq, seqs);
}

struct mailbox *
mailbox_transaction_get_mailbox(const struct mailbox_transaction_context *t)
{
	return t->box;
}

static void mailbox_save_dest_mail_close(struct mail_save_context *ctx)
{
	struct mail_private *mail = (struct mail_private *)ctx->dest_mail;

	mail->v.close(&mail->mail);
}

struct mail_save_context *
mailbox_save_alloc(struct mailbox_transaction_context *t)
{
	struct mail_save_context *ctx;
	const struct mail_storage_settings *mail_set =
		mailbox_get_settings(t->box);
	T_BEGIN {
		ctx = t->box->v.save_alloc(t);
	} T_END;
	i_assert(!ctx->unfinished);
	ctx->unfinished = TRUE;
	ctx->data.received_date = (time_t)-1;
	ctx->data.save_date = (time_t)-1;

	/* Always have a dest_mail available. A lot of plugins make use
	   of this. */
	if (ctx->dest_mail == NULL)
		ctx->dest_mail = mail_alloc(t, 0, NULL);
	else {
		/* make sure the mail isn't used before mail_set_seq_saving() */
		mailbox_save_dest_mail_close(ctx);
	}

	/* make sure parts get parsed early on */
	if (mail_set->parsed_mail_attachment_detection_add_flags_on_save)
		mail_add_temp_wanted_fields(ctx->dest_mail,
					    MAIL_FETCH_MESSAGE_PARTS, NULL);

	return ctx;
}

void mailbox_save_context_deinit(struct mail_save_context *ctx)
{
	i_assert(ctx->dest_mail != NULL);

	mail_free(&ctx->dest_mail);
}

void mailbox_save_set_flags(struct mail_save_context *ctx,
			    enum mail_flags flags,
			    struct mail_keywords *keywords)
{
	struct mailbox *box = ctx->transaction->box;

	if (ctx->data.keywords != NULL)
		mailbox_keywords_unref(&ctx->data.keywords);

	ctx->data.flags = flags & ~mailbox_get_private_flags_mask(box);
	ctx->data.pvt_flags = flags & mailbox_get_private_flags_mask(box);
	ctx->data.keywords = keywords;
	if (keywords != NULL)
		mailbox_keywords_ref(keywords);
}

void mailbox_save_copy_flags(struct mail_save_context *ctx, struct mail *mail)
{
	const char *const *keywords_list;
	struct mail_keywords *keywords;

	keywords_list = mail_get_keywords(mail);
	keywords = str_array_length(keywords_list) == 0 ? NULL :
		mailbox_keywords_create_valid(ctx->transaction->box,
					      keywords_list);
	mailbox_save_set_flags(ctx, mail_get_flags(mail), keywords);
	if (keywords != NULL)
		mailbox_keywords_unref(&keywords);
}

void mailbox_save_set_min_modseq(struct mail_save_context *ctx,
				 uint64_t min_modseq)
{
	ctx->data.min_modseq = min_modseq;
}

void mailbox_save_set_received_date(struct mail_save_context *ctx,
				    time_t received_date, int timezone_offset)
{
	ctx->data.received_date = received_date;
	ctx->data.received_tz_offset = timezone_offset;
}

void mailbox_save_set_save_date(struct mail_save_context *ctx,
				time_t save_date)
{
	ctx->data.save_date = save_date;
}

void mailbox_save_set_from_envelope(struct mail_save_context *ctx,
				    const char *envelope)
{
	i_free(ctx->data.from_envelope);
	ctx->data.from_envelope = i_strdup(envelope);
}

void mailbox_save_set_uid(struct mail_save_context *ctx, uint32_t uid)
{
	ctx->data.uid = uid;
	if ((ctx->transaction->flags & MAILBOX_TRANSACTION_FLAG_FILL_IN_STUB) != 0) {
		if (!mail_index_lookup_seq(ctx->transaction->view, uid,
					   &ctx->data.stub_seq))
			i_panic("Trying to fill in stub for nonexistent UID %u", uid);
	}
}

void mailbox_save_set_guid(struct mail_save_context *ctx, const char *guid)
{
	i_assert(guid == NULL || *guid != '\0');

	i_free(ctx->data.guid);
	ctx->data.guid = i_strdup(guid);
}

void mailbox_save_set_pop3_uidl(struct mail_save_context *ctx, const char *uidl)
{
	i_assert(*uidl != '\0');
	i_assert(strchr(uidl, '\n') == NULL);

	i_free(ctx->data.pop3_uidl);
	ctx->data.pop3_uidl = i_strdup(uidl);
}

void mailbox_save_set_pop3_order(struct mail_save_context *ctx,
				 unsigned int order)
{
	i_assert(order > 0);

	ctx->data.pop3_order = order;
}

struct mail *mailbox_save_get_dest_mail(struct mail_save_context *ctx)
{
	return ctx->dest_mail;
}

int mailbox_save_begin(struct mail_save_context **ctx, struct istream *input)
{
	struct mailbox *box = (*ctx)->transaction->box;
	int ret;

	if (mail_index_is_deleted(box->index)) {
		mailbox_set_deleted(box);
		mailbox_save_cancel(ctx);
		return -1;
	}

	/* if we're filling in a stub, we must have set UID already
	   (which in turn sets stub_seq) */
	i_assert(((*ctx)->transaction->flags & MAILBOX_TRANSACTION_FLAG_FILL_IN_STUB) == 0 ||
		 (*ctx)->data.stub_seq != 0);

	if (!(*ctx)->copying_or_moving) {
		/* We're actually saving the mail. We're not being called by
		   mail_storage_copy() because backend didn't support fast
		   copying. */
		i_assert(!(*ctx)->copying_via_save);
		(*ctx)->saving = TRUE;
	} else {
		i_assert((*ctx)->copying_via_save);
	}
	if (box->v.save_begin == NULL) {
		mail_storage_set_error(box->storage, MAIL_ERROR_NOTPOSSIBLE,
				       "Saving messages not supported");
		ret = -1;
	} else T_BEGIN {
		ret = box->v.save_begin(*ctx, input);
	} T_END;

	if (ret < 0) {
		mailbox_save_cancel(ctx);
		return -1;
	}
	return 0;
}

int mailbox_save_continue(struct mail_save_context *ctx)
{
	int ret;

	T_BEGIN {
		ret = ctx->transaction->box->v.save_continue(ctx);
	} T_END;
	return ret;
}

static void
mailbox_save_add_pvt_flags(struct mailbox_transaction_context *t,
			   enum mail_flags pvt_flags)
{
	struct mail_save_private_changes *save;

	if (!array_is_created(&t->pvt_saves))
		i_array_init(&t->pvt_saves, 8);
	save = array_append_space(&t->pvt_saves);
	save->mailnum = t->save_count;
	save->flags = pvt_flags;
}

static void
mailbox_save_context_reset(struct mail_save_context *ctx, bool success)
{
	i_assert(!ctx->unfinished);
	if (!ctx->copying_or_moving) {
		/* we're finishing a save (not copy/move). Note that we could
		   have come here also from mailbox_save_cancel(), in which
		   case ctx->saving may be FALSE. */
		i_assert(!ctx->copying_via_save);
		i_assert(ctx->saving || !success);
		ctx->saving = FALSE;
	} else {
		i_assert(ctx->copying_via_save || !success);
		/* We came from mailbox_copy(). saving==TRUE is possible here
		   if we also came from mailbox_save_using_mail(). Don't set
		   saving=FALSE yet in that case, because copy() is still
		   running. */
	}
}

int mailbox_save_finish(struct mail_save_context **_ctx)
{
	struct mail_save_context *ctx = *_ctx;
	struct mailbox_transaction_context *t = ctx->transaction;
	/* we need to keep a copy of this because save_finish implementations
	   will likely zero the data structure during cleanup */
	struct mail_keywords *keywords = ctx->data.keywords;
	enum mail_flags pvt_flags = ctx->data.pvt_flags;
	bool copying_via_save = ctx->copying_via_save;
	int ret;

	/* Do one final continue. The caller may not have done it if the
	   input stream's offset already matched the number of bytes that
	   were wanted to be saved. But due to nested istreams some of the
	   underlying ones may not have seen the EOF yet, and haven't flushed
	   out the pending data. */
	if (mailbox_save_continue(ctx) < 0) {
		mailbox_save_cancel(_ctx);
		return -1;
	}
	*_ctx = NULL;

	ctx->finishing = TRUE;
	T_BEGIN {
		ret = t->box->v.save_finish(ctx);
	} T_END;
	ctx->finishing = FALSE;

	if (ret == 0 && !copying_via_save) {
		if (pvt_flags != 0)
			mailbox_save_add_pvt_flags(t, pvt_flags);
		t->save_count++;
	}

	if (keywords != NULL)
		mailbox_keywords_unref(&keywords);
	mailbox_save_context_reset(ctx, TRUE);
	return ret;
}

void mailbox_save_cancel(struct mail_save_context **_ctx)
{
	struct mail_save_context *ctx = *_ctx;
	struct mail_keywords *keywords = ctx->data.keywords;

	*_ctx = NULL;
	T_BEGIN {
		ctx->transaction->box->v.save_cancel(ctx);
	} T_END;
	if (keywords != NULL && !ctx->finishing)
		mailbox_keywords_unref(&keywords);

	/* the dest_mail is no longer valid. if we're still saving
	   more mails, the mail sequence may get reused. make sure
	   the mail gets reset in between */
	mailbox_save_dest_mail_close(ctx);

	mailbox_save_context_reset(ctx, FALSE);
}

struct mailbox_transaction_context *
mailbox_save_get_transaction(struct mail_save_context *ctx)
{
	return ctx->transaction;
}

static int mailbox_copy_int(struct mail_save_context **_ctx, struct mail *mail)
{
	struct mail_save_context *ctx = *_ctx;
	struct mailbox_transaction_context *t = ctx->transaction;
	struct mail_keywords *keywords = ctx->data.keywords;
	enum mail_flags pvt_flags = ctx->data.pvt_flags;
	struct mail *backend_mail;
	int ret;

	*_ctx = NULL;

	if (mail_index_is_deleted(t->box->index)) {
		mailbox_set_deleted(t->box);
		mailbox_save_cancel(&ctx);
		return -1;
	}

	/* bypass virtual storage, so hard linking can be used whenever
	   possible */
	if (mail_get_backend_mail(mail, &backend_mail) < 0) {
		mailbox_save_cancel(&ctx);
		return -1;
	}

	i_assert(!ctx->copying_or_moving);
	i_assert(ctx->copy_src_mail == NULL);
	ctx->copying_or_moving = TRUE;
	ctx->copy_src_mail = mail;
	ctx->finishing = TRUE;
	T_BEGIN {
		ret = t->box->v.copy(ctx, backend_mail);
	} T_END;
	ctx->finishing = FALSE;
	if (ret == 0) {
		if (pvt_flags != 0)
			mailbox_save_add_pvt_flags(t, pvt_flags);
		t->save_count++;
	}
	if (keywords != NULL)
		mailbox_keywords_unref(&keywords);
	i_assert(!ctx->unfinished);

	ctx->copy_src_mail = NULL;
	ctx->copying_via_save = FALSE;
	ctx->copying_or_moving = FALSE;
	ctx->saving = FALSE; /* if we came from mailbox_save_using_mail() */
	return ret;
}

int mailbox_copy(struct mail_save_context **_ctx, struct mail *mail)
{
	struct mail_save_context *ctx = *_ctx;

	i_assert(!ctx->saving);
	i_assert(!ctx->moving);

	return mailbox_copy_int(_ctx, mail);
}

int mailbox_move(struct mail_save_context **_ctx, struct mail *mail)
{
	struct mail_save_context *ctx = *_ctx;
	int ret;

	i_assert(!ctx->saving);
	i_assert(!ctx->moving);

	ctx->moving = TRUE;
	if ((ret = mailbox_copy_int(_ctx, mail)) == 0)
		mail_expunge(mail);
	ctx->moving = FALSE;
	return ret;
}

int mailbox_save_using_mail(struct mail_save_context **_ctx, struct mail *mail)
{
	struct mail_save_context *ctx = *_ctx;

	i_assert(!ctx->saving);
	i_assert(!ctx->moving);

	ctx->saving = TRUE;
	return mailbox_copy_int(_ctx, mail);
}

bool mailbox_is_inconsistent(struct mailbox *box)
{
	return box->mailbox_deleted || box->v.is_inconsistent(box);
}

void mailbox_set_deleted(struct mailbox *box)
{
	mail_storage_set_error(box->storage, MAIL_ERROR_NOTFOUND,
			       "Mailbox was deleted under us");
	box->mailbox_deleted = TRUE;
}

static int get_path_to(struct mailbox *box, enum mailbox_list_path_type type,
		       const char **internal_path, const char **path_r)
{
	int ret;

	if (internal_path != NULL && *internal_path != NULL) {
		if ((*internal_path)[0] == '\0') {
			*path_r = NULL;
			return 0;
		}
		*path_r = *internal_path;
		return 1;
	}
	ret = mailbox_list_get_path(box->list, box->name, type, path_r);
	if (ret < 0) {
		mail_storage_copy_list_error(box->storage, box->list);
		return -1;
	}
	if (internal_path != NULL && *internal_path == NULL)
		*internal_path = ret == 0 ? "" : p_strdup(box->pool, *path_r);
	return ret;
}

int mailbox_get_path_to(struct mailbox *box, enum mailbox_list_path_type type,
			const char **path_r)
{
	if (type == MAILBOX_LIST_PATH_TYPE_MAILBOX)
		return get_path_to(box, type, &box->_path, path_r);
	if (type == MAILBOX_LIST_PATH_TYPE_INDEX)
		return get_path_to(box, type, &box->_index_path, path_r);
	return get_path_to(box, type, NULL, path_r);
}

const char *mailbox_get_path(struct mailbox *box)
{
	i_assert(box->_path != NULL);
	i_assert(box->_path[0] != '\0');
	return box->_path;
}

const char *mailbox_get_index_path(struct mailbox *box)
{
	i_assert(box->_index_path != NULL);
	i_assert(box->_index_path[0] != '\0');
	return box->_index_path;
}

static void mailbox_get_permissions_if_not_set(struct mailbox *box)
{
	if (box->_perm.file_create_mode != 0)
		return;

	if (box->input != NULL) {
		box->_perm.file_uid = geteuid();
		box->_perm.file_create_mode = 0600;
		box->_perm.dir_create_mode = 0700;
		box->_perm.file_create_gid = (gid_t)-1;
		box->_perm.file_create_gid_origin = "defaults";
		return;
	}

	struct mailbox_permissions perm;
	mailbox_list_get_permissions(box->list, box->name, &perm);
	mailbox_permissions_copy(&box->_perm, &perm, box->pool);
}

const struct mailbox_permissions *mailbox_get_permissions(struct mailbox *box)
{
	mailbox_get_permissions_if_not_set(box);

	if (!box->_perm.mail_index_permissions_set && box->index != NULL) {
		box->_perm.mail_index_permissions_set = TRUE;
		mail_index_set_permissions(box->index,
					   box->_perm.file_create_mode,
					   box->_perm.file_create_gid,
					   box->_perm.file_create_gid_origin);
	}
	return &box->_perm;
}

void mailbox_refresh_permissions(struct mailbox *box)
{
	i_zero(&box->_perm);
	(void)mailbox_get_permissions(box);
}

int mailbox_create_fd(struct mailbox *box, const char *path, int flags,
		      int *fd_r)
{
	const struct mailbox_permissions *perm = mailbox_get_permissions(box);
	mode_t old_mask;
	int fd;

	i_assert((flags & O_CREAT) != 0);

	*fd_r = -1;

	old_mask = umask(0);
	fd = open(path, flags, perm->file_create_mode);
	umask(old_mask);

	if (fd != -1) {
		/* ok */
	} else if (errno == EEXIST) {
		/* O_EXCL used, caller will handle this error */
		return 0;
	} else if (errno == ENOENT) {
		mailbox_set_deleted(box);
		return -1;
	} else if (errno == ENOTDIR) {
		mail_storage_set_error(box->storage, MAIL_ERROR_NOTPOSSIBLE,
			"Mailbox doesn't allow inferior mailboxes");
		return -1;
	} else if (mail_storage_set_error_from_errno(box->storage)) {
		return -1;
	} else {
		mailbox_set_critical(box, "open(%s, O_CREAT) failed: %m", path);
		return -1;
	}

	if (perm->file_create_gid != (gid_t)-1) {
		if (fchown(fd, (uid_t)-1, perm->file_create_gid) == 0) {
			/* ok */
		} else if (errno == EPERM) {
			mailbox_set_critical(box, "%s",
				eperm_error_get_chgrp("fchown", path,
					perm->file_create_gid,
					perm->file_create_gid_origin));
		} else {
			mailbox_set_critical(box,
				"fchown(%s) failed: %m", path);
		}
	}
	*fd_r = fd;
	return 1;
}

int mailbox_mkdir(struct mailbox *box, const char *path,
		  enum mailbox_list_path_type type)
{
	const struct mailbox_permissions *perm = mailbox_get_permissions(box);
	const char *root_dir;

	if (!perm->gid_origin_is_mailbox_path) {
		/* mailbox root directory doesn't exist, create it */
		root_dir = mailbox_list_get_root_forced(box->list, type);
		if (mailbox_list_mkdir_root(box->list, root_dir, type) < 0) {
			mail_storage_copy_list_error(box->storage, box->list);
			return -1;
		}
	}

	if (mkdir_parents_chgrp(path, perm->dir_create_mode,
				perm->file_create_gid,
				perm->file_create_gid_origin) == 0)
		return 1;
	else if (errno == EEXIST)
		return 0;
	else if (errno == ENOTDIR) {
		mail_storage_set_error(box->storage, MAIL_ERROR_NOTPOSSIBLE,
			"Mailbox doesn't allow inferior mailboxes");
		return -1;
	} else if (mail_storage_set_error_from_errno(box->storage)) {
		return -1;
	} else {
		mailbox_set_critical(box, "mkdir_parents(%s) failed: %m", path);
		return -1;
	}
}

int mailbox_create_missing_dir(struct mailbox *box,
			       enum mailbox_list_path_type type)
{
	const char *mail_dir, *dir;
	struct stat st;
	int ret;

	if ((ret = mailbox_get_path_to(box, type, &dir)) <= 0)
		return ret;
	if (mailbox_get_path_to(box, MAILBOX_LIST_PATH_TYPE_MAILBOX,
				&mail_dir) < 0)
		return -1;
	if (null_strcmp(dir, mail_dir) != 0) {
		/* Mailbox directory is different - create a missing dir */
	} else if ((box->list->props & MAILBOX_LIST_PROP_AUTOCREATE_DIRS) != 0) {
		/* This layout (e.g. imapc) wants to autocreate missing mailbox
		   directories as well. */
	} else {
		/* If the mailbox directory doesn't exist, the mailbox
		   shouldn't exist at all. So just assume that it's already
		   created and if there's a race condition just fail later. */
		return 0;
	}

	/* we call this function even when the directory exists, so first do a
	   quick check to see if we need to mkdir anything */
	if (stat(dir, &st) == 0)
		return 0;

	if ((box->storage->class_flags & MAIL_STORAGE_CLASS_FLAG_NO_ROOT) == 0 &&
	    null_strcmp(dir, mail_dir) != 0 && mail_dir != NULL &&
	    stat(mail_dir, &st) < 0 && (errno == ENOENT || errno == ENOTDIR)) {
		/* Race condition - mail root directory doesn't exist
		   anymore either. We shouldn't create this directory
		   anymore. */
		mailbox_set_deleted(box);
		return -1;
	}

	return mailbox_mkdir(box, dir, type);
}

unsigned int mail_storage_get_lock_timeout(struct mail_storage *storage,
					   unsigned int secs)
{
	return storage->set->mail_max_lock_timeout == 0 ? secs :
		I_MIN(secs, storage->set->mail_max_lock_timeout);
}

enum mail_index_open_flags
mail_storage_settings_to_index_flags(const struct mail_storage_settings *set)
{
	enum mail_index_open_flags index_flags = 0;

#ifndef MMAP_CONFLICTS_WRITE
	if (set->mmap_disable)
#endif
		index_flags |= MAIL_INDEX_OPEN_FLAG_MMAP_DISABLE;
	if (set->dotlock_use_excl)
		index_flags |= MAIL_INDEX_OPEN_FLAG_DOTLOCK_USE_EXCL;
	if (set->mail_nfs_index)
		index_flags |= MAIL_INDEX_OPEN_FLAG_NFS_FLUSH;
	return index_flags;
}

int mail_parse_human_timestamp(const char *str, time_t *timestamp_r,
			       bool *utc_r)
{
	struct tm tm;
	unsigned int secs;
	const char *error;

	if (i_isdigit(str[0]) && i_isdigit(str[1]) &&
	    i_isdigit(str[2]) && i_isdigit(str[3]) && str[4] == '-' &&
	    i_isdigit(str[5]) && i_isdigit(str[6]) && str[7] == '-' &&
	    i_isdigit(str[8]) && i_isdigit(str[9]) && str[10] == '\0') {
		/* yyyy-mm-dd */
		i_zero(&tm);
		tm.tm_year = (str[0]-'0') * 1000 + (str[1]-'0') * 100 +
			(str[2]-'0') * 10 + (str[3]-'0') - 1900;
		tm.tm_mon = (str[5]-'0') * 10 + (str[6]-'0') - 1;
		tm.tm_mday = (str[8]-'0') * 10 + (str[9]-'0');
		*timestamp_r = mktime(&tm);
		*utc_r = FALSE;
		return 0;
	} else if (imap_parse_date(str, timestamp_r)) {
		/* imap date */
		*utc_r = FALSE;
		return 0;
	} else if (str_to_time(str, timestamp_r) == 0) {
		/* unix timestamp */
		*utc_r = TRUE;
		return 0;
	} else if (settings_get_time(str, &secs, &error) == 0) {
		*timestamp_r = ioloop_time - secs;
		*utc_r = TRUE;
		return 0;
	} else {
		return -1;
	}
}

void mail_set_mail_cache_corrupted(struct mail *mail, const char *fmt, ...)
{
	struct mail_cache_view *cache_view =
		mail->transaction->cache_view;

	i_assert(cache_view != NULL);

	va_list va;
	va_start(va, fmt);

	T_BEGIN {
		mail_cache_set_seq_corrupted_reason(cache_view, mail->seq,
			t_strdup_printf("UID %u: %s",
					mail->uid,
					t_strdup_vprintf(fmt, va)));
	} T_END;

	/* update also the storage's internal error */
	mailbox_set_index_error(mail->box);

	va_end(va);
}

static int
mail_storage_dotlock_create(const char *lock_path,
			    const struct file_create_settings *lock_set,
			    const struct mail_storage_settings *mail_set,
			    struct file_lock **lock_r, const char **error_r)
{
	const struct dotlock_settings dotlock_set = {
		.timeout = lock_set->lock_timeout_secs,
		.stale_timeout = I_MAX(60*5, lock_set->lock_timeout_secs),
		.lock_suffix = "",

		.use_excl_lock = mail_set->dotlock_use_excl,
		.nfs_flush = mail_set->mail_nfs_storage,
		.use_io_notify = TRUE,
	};
	struct dotlock *dotlock;
	int ret = file_dotlock_create(&dotlock_set, lock_path, 0, &dotlock);
	if (ret <= 0) {
		*error_r = t_strdup_printf("file_dotlock_create(%s) failed: %m",
					   lock_path);
		return ret;
	}
	*lock_r = file_lock_from_dotlock(&dotlock);
	return 1;
}

int mail_storage_lock_create(const char *lock_path,
			     const struct file_create_settings *lock_set,
			     const struct mail_storage_settings *mail_set,
			     struct file_lock **lock_r, const char **error_r)
{
	bool created;

	if (lock_set->lock_method == FILE_LOCK_METHOD_DOTLOCK)
		return mail_storage_dotlock_create(lock_path, lock_set, mail_set, lock_r, error_r);

	if (file_create_locked(lock_path, lock_set, lock_r,
			       &created, error_r) == -1) {
		*error_r = t_strdup_printf("file_create_locked(%s) failed: %s",
					   lock_path, *error_r);
		return errno == EAGAIN ? 0 : -1;
	}
	file_lock_set_close_on_free(*lock_r, TRUE);
	file_lock_set_unlink_on_free(*lock_r, TRUE);
	return 1;
}

int mailbox_lock_file_create(struct mailbox *box, const char *lock_fname,
			     unsigned int lock_secs, struct file_lock **lock_r,
			     const char **error_r)
{
	const struct mailbox_permissions *perm;
	struct file_create_settings set;
	const char *lock_path;

	perm = mailbox_get_permissions(box);
	i_zero(&set);
	set.lock_timeout_secs =
		mail_storage_get_lock_timeout(box->storage, lock_secs);
	set.lock_method = box->storage->set->parsed_lock_method;
	set.mode = perm->file_create_mode;
	set.gid = perm->file_create_gid;
	set.gid_origin = perm->file_create_gid_origin;

	if (box->list->set.volatile_dir == NULL)
		lock_path = t_strdup_printf("%s/%s", box->index->dir, lock_fname);
	else {
		unsigned char box_name_sha1[SHA1_RESULTLEN];
		string_t *str = t_str_new(128);

		/* Keep this simple: Use the lock_fname with a SHA1 of the
		   mailbox name as the suffix. The mailbox name itself could
		   be too large as a filename and creating the full directory
		   structure would be pretty troublesome. It would also make
		   it more difficult to perform the automated deletion of empty
		   lock directories. */
		str_printfa(str, "%s/%s.", box->list->set.volatile_dir,
			    lock_fname);
		sha1_get_digest(box->name, strlen(box->name), box_name_sha1);
		binary_to_hex_append(str, box_name_sha1, sizeof(box_name_sha1));
		lock_path = str_c(str);
		set.mkdir_mode = 0700;
	}

	return mail_storage_lock_create(lock_path, &set,
					box->storage->set, lock_r, error_r);
}
