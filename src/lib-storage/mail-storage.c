/* Copyright (C) 2002-2003 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "mail-storage-private.h"

#include <stdlib.h>
#include <time.h>
#include <ctype.h>

/* Message to show to users when critical error occurs */
#define CRITICAL_MSG \
	"Internal error occured. Error report written to server log."
#define CRITICAL_MSG_STAMP CRITICAL_MSG " [%Y-%m-%d %H:%M:%S]"

struct mail_storage_list {
	struct mail_storage_list *next;
	struct mail_storage *storage;
};

static struct mail_storage_list *storages = NULL;
int full_filesystem_access = FALSE;

void mail_storage_init(void)
{
        full_filesystem_access = getenv("FULL_FILESYSTEM_ACCESS") != NULL;
}

void mail_storage_deinit(void)
{
	struct mail_storage_list *next;

	while (storages != NULL) {
		next = storages->next;

		i_free(storages);
                storages = next;
	}
}

void mail_storage_class_register(struct mail_storage *storage_class)
{
	struct mail_storage_list *list, **pos;

	list = i_new(struct mail_storage_list, 1);
	list->storage = storage_class;

	/* append it after the list, so the autodetection order is correct */
	pos = &storages;
	while (*pos != NULL)
		pos = &(*pos)->next;
	*pos = list;
}

void mail_storage_class_unregister(struct mail_storage *storage_class)
{
	struct mail_storage_list **list, *next;

	for (list = &storages; *list != NULL; list = &(*list)->next) {
		if ((*list)->storage == storage_class) {
			next = (*list)->next;

			mail_storage_destroy((*list)->storage);
			i_free(*list);

			*list = next;
		}
	}
}

struct mail_storage *
mail_storage_create(const char *name, const char *data, const char *user,
		    const char *namespace, char hierarchy_sep)
{
	struct mail_storage_list *list;

	i_assert(name != NULL);

	for (list = storages; list != NULL; list = list->next) {
		if (strcasecmp(list->storage->name, name) == 0) {
			return list->storage->create(data, user,
						     namespace, hierarchy_sep);
		}
	}

	return NULL;
}

struct mail_storage *
mail_storage_create_default(const char *user,
			    const char *namespace, char hierarchy_sep)
{
	struct mail_storage_list *list;
	struct mail_storage *storage;

	for (list = storages; list != NULL; list = list->next) {
		storage = list->storage->create(NULL, user, namespace,
						hierarchy_sep);
		if (storage != NULL)
			return storage;
	}

	return NULL;
}

static struct mail_storage *mail_storage_autodetect(const char *data)
{
	struct mail_storage_list *list;

	for (list = storages; list != NULL; list = list->next) {
		if (list->storage->autodetect(data))
			return list->storage;
	}

	return NULL;
}

struct mail_storage *
mail_storage_create_with_data(const char *data, const char *user,
			      const char *namespace, char hierarchy_sep)
{
	struct mail_storage *storage;
	const char *p, *name;

	if (data == NULL || *data == '\0') {
		return mail_storage_create_default(user, namespace,
						   hierarchy_sep);
	}

	/* check if we're in the form of mailformat:data
	   (eg. maildir:Maildir) */
	p = data;
	while (i_isalnum(*p)) p++;

	if (*p == ':') {
		name = t_strdup_until(data, p);
		storage = mail_storage_create(name, p+1, user,
					      namespace, hierarchy_sep);
	} else {
		storage = mail_storage_autodetect(data);
		if (storage != NULL) {
			storage = storage->create(data, user,
						  namespace, hierarchy_sep);
		}
	}

	return storage;
}

void mail_storage_destroy(struct mail_storage *storage)
{
	i_assert(storage != NULL);

	storage->destroy(storage);
}

void mail_storage_clear_error(struct mail_storage *storage)
{
	i_free(storage->error);
	storage->error = NULL;

	storage->syntax_error = FALSE;
}

void mail_storage_set_error(struct mail_storage *storage, const char *fmt, ...)
{
	va_list va;

	i_free(storage->error);

	if (fmt == NULL)
		storage->error = NULL;
	else {
		va_start(va, fmt);
		storage->error = i_strdup_vprintf(fmt, va);
		storage->syntax_error = FALSE;
		va_end(va);
	}
}

void mail_storage_set_syntax_error(struct mail_storage *storage,
				   const char *fmt, ...)
{
	va_list va;

	i_free(storage->error);

	if (fmt == NULL)
		storage->error = NULL;
	else {
		va_start(va, fmt);
		storage->error = i_strdup_vprintf(fmt, va);
		storage->syntax_error = TRUE;
		va_end(va);
	}
}

void mail_storage_set_internal_error(struct mail_storage *storage)
{
	struct tm *tm;
	char str[256];

	tm = localtime(&ioloop_time);

	i_free(storage->error);
	storage->error =
		strftime(str, sizeof(str), CRITICAL_MSG_STAMP, tm) > 0 ?
		i_strdup(str) : i_strdup(CRITICAL_MSG);
	storage->syntax_error = FALSE;
}

void mail_storage_set_critical(struct mail_storage *storage,
			       const char *fmt, ...)
{
	va_list va;

	i_free(storage->error);
	if (fmt == NULL)
		storage->error = NULL;
	else {
		va_start(va, fmt);
		i_error("%s", t_strdup_vprintf(fmt, va));
		va_end(va);

		/* critical errors may contain sensitive data, so let user
		   see only "Internal error" with a timestamp to make it
		   easier to look from log files the actual error message. */
		mail_storage_set_internal_error(storage);
	}
}

char mail_storage_get_hierarchy_sep(struct mail_storage *storage)
{
	return storage->hierarchy_sep;
}

void mail_storage_set_callbacks(struct mail_storage *storage,
				struct mail_storage_callbacks *callbacks,
				void *context)
{
	storage->set_callbacks(storage, callbacks, context);
}

int mail_storage_mailbox_create(struct mail_storage *storage, const char *name,
				int directory)
{
	return storage->mailbox_create(storage, name, directory);
}

int mail_storage_mailbox_delete(struct mail_storage *storage, const char *name)
{
	return storage->mailbox_delete(storage, name);
}

int mail_storage_mailbox_rename(struct mail_storage *storage,
				const char *oldname, const char *newname)
{
	return storage->mailbox_rename(storage, oldname, newname);
}

struct mailbox_list_context *
mail_storage_mailbox_list_init(struct mail_storage *storage,
			       const char *mask,
			       enum mailbox_list_flags flags)
{
	return storage->mailbox_list_init(storage, mask, flags);
}

struct mailbox_list *
mail_storage_mailbox_list_next(struct mailbox_list_context *ctx)
{
	return ctx->storage->mailbox_list_next(ctx);
}

int mail_storage_mailbox_list_deinit(struct mailbox_list_context *ctx)
{
	return ctx->storage->mailbox_list_deinit(ctx);
}

int mail_storage_set_subscribed(struct mail_storage *storage,
				const char *name, int set)
{
	return storage->set_subscribed(storage, name, set);
}

int mail_storage_get_mailbox_name_status(struct mail_storage *storage,
					 const char *name,
					 enum mailbox_name_status *status)
{
	return storage->get_mailbox_name_status(storage, name, status);
}

const char *mail_storage_get_last_error(struct mail_storage *storage,
					int *syntax_error_r)
{
	return storage->get_last_error(storage, syntax_error_r);
}

struct mailbox *mailbox_open(struct mail_storage *storage,
			     const char *name, enum mailbox_open_flags flags)
{
	return storage->mailbox_open(storage, name, flags);
}

int mailbox_close(struct mailbox *box)
{
	return box->close(box);
}

struct mail_storage *mailbox_get_storage(struct mailbox *box)
{
	return box->storage;
}

const char *mailbox_get_name(struct mailbox *box)
{
	return box->name;
}

int mailbox_is_readonly(struct mailbox *box)
{
	return box->is_readonly(box);
}

int mailbox_allow_new_keywords(struct mailbox *box)
{
	return box->allow_new_keywords(box);
}

int mailbox_get_status(struct mailbox *box,
		       enum mailbox_status_items items,
		       struct mailbox_status *status)
{
	return box->get_status(box, items, status);
}

int mailbox_sync(struct mailbox *box, enum mailbox_sync_flags flags)
{
	return box->sync(box, flags);
}

void mailbox_auto_sync(struct mailbox *box, enum mailbox_sync_flags flags,
		       unsigned int min_newmail_notify_interval)
{
	box->auto_sync(box, flags, min_newmail_notify_interval);
}

struct mail *mailbox_fetch(struct mailbox_transaction_context *t, uint32_t seq,
			   enum mail_fetch_field wanted_fields)
{
	return t->box->fetch(t, seq, wanted_fields);
}

int mailbox_get_uids(struct mailbox *box, uint32_t uid1, uint32_t uid2,
		     uint32_t *seq1_r, uint32_t *seq2_r)
{
	return box->get_uids(box, uid1, uid2, seq1_r, seq2_r);
}

int mailbox_search_get_sorting(struct mailbox *box,
			       enum mail_sort_type *sort_program)
{
	return box->search_get_sorting(box, sort_program);
}

struct mail_search_context *
mailbox_search_init(struct mailbox_transaction_context *t,
		    const char *charset, struct mail_search_arg *args,
		    const enum mail_sort_type *sort_program,
		    enum mail_fetch_field wanted_fields,
		    const char *const wanted_headers[])
{
	return t->box->search_init(t, charset, args, sort_program,
				   wanted_fields, wanted_headers);
}

int mailbox_search_deinit(struct mail_search_context *ctx)
{
	return ctx->box->search_deinit(ctx);
}

struct mail *mailbox_search_next(struct mail_search_context *ctx)
{
	return ctx->box->search_next(ctx);
}

struct mailbox_transaction_context *
mailbox_transaction_begin(struct mailbox *box, int hide)
{
	return box->transaction_begin(box, hide);
}

int mailbox_transaction_commit(struct mailbox_transaction_context *t)
{
	return t->box->transaction_commit(t);
}

void mailbox_transaction_rollback(struct mailbox_transaction_context *t)
{
	t->box->transaction_rollback(t);
}

int mailbox_save(struct mailbox_transaction_context *t,
		 const struct mail_full_flags *flags,
		 time_t received_date, int timezone_offset,
		 const char *from_envelope, struct istream *data,
		 struct mail **mail_r)
{
	return t->box->save(t, flags, received_date, timezone_offset,
			    from_envelope, data, mail_r);
}

int mailbox_copy(struct mailbox_transaction_context *t, struct mail *mail,
		 struct mail **dest_mail_r)
{
	return t->box->copy(t, mail, dest_mail_r);
}

int mailbox_is_inconsistent(struct mailbox *box)
{
	return box->is_inconsistent(box);
}
