/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "mail-storage.h"

#include <ctype.h>

typedef struct _MailStorageList MailStorageList;

struct _MailStorageList {
	MailStorageList *next;
	MailStorage *storage;
};

static MailStorageList *storages = NULL;

void mail_storage_class_register(MailStorage *storage_class)
{
	MailStorageList *list, **pos;

	list = i_new(MailStorageList, 1);
	list->storage = storage_class;

	/* append it after the list, so the autodetection order is correct */
	pos = &storages;
	while (*pos != NULL)
		pos = &(*pos)->next;
	*pos = list;
}

void mail_storage_class_unregister(MailStorage *storage_class)
{
	MailStorageList **list, *next;

	for (list = &storages; *list != NULL; list = &(*list)->next) {
		if ((*list)->storage == storage_class) {
			next = (*list)->next;

			(*list)->storage->free((*list)->storage);
			i_free(*list);

			*list = next;
		}
	}
}

MailStorage *mail_storage_create(const char *name, const char *data)
{
	MailStorageList *list;

	i_assert(name != NULL);

	for (list = storages; list != NULL; list = list->next) {
		if (strcasecmp(list->storage->name, name) == 0)
			return list->storage->create(data);
	}

	return NULL;
}

MailStorage *mail_storage_create_default(void)
{
	MailStorageList *list;
	MailStorage *storage;

	for (list = storages; list != NULL; list = list->next) {
		storage = list->storage->create(NULL);
		if (storage != NULL)
			return storage;
	}

	return NULL;
}

static MailStorage *mail_storage_autodetect(const char *data)
{
	MailStorageList *list;

	for (list = storages; list != NULL; list = list->next) {
		if (list->storage->autodetect(data))
			return list->storage;
	}

	return NULL;
}

MailStorage *mail_storage_create_with_data(const char *data)
{
	MailStorage *storage;
	const char *p, *name;

	if (data == NULL || *data == '\0')
		return mail_storage_create_default();

	/* check if we're in the form of mailformat:data
	   (eg. maildir:Maildir) */
	p = data;
	while (i_isalnum(*p)) p++;

	if (*p == ':') {
		name = t_strdup_until(data, p);
		storage = mail_storage_create(name, p+1);
	} else {
		storage = mail_storage_autodetect(data);
		if (storage != NULL)
			storage = storage->create(data);
	}

	return storage;
}

void mail_storage_destroy(MailStorage *storage)
{
	i_assert(storage != NULL);

	i_free(storage->dir);
	i_free(storage);
}

void mail_storage_clear_error(MailStorage *storage)
{
	i_free(storage->error);
	storage->error = NULL;
}

void mail_storage_set_error(MailStorage *storage, const char *fmt, ...)
{
	va_list va;

	i_free(storage->error);

	if (fmt == NULL)
		storage->error = NULL;
	else {
		va_start(va, fmt);
		storage->error = i_strdup_vprintf(fmt, va);
		va_end(va);
	}
}

void mail_storage_set_critical(MailStorage *storage, const char *fmt, ...)
{
	va_list va;

	i_free(storage->error);

	if (fmt == NULL)
		storage->error = NULL;
	else {
		va_start(va, fmt);
		storage->error = i_strdup_vprintf(fmt, va);
		va_end(va);

		i_error("%s", storage->error);
	}
}

const char *mail_storage_get_last_error(MailStorage *storage)
{
	return storage->error;
}

int mail_storage_is_inconsistency_error(Mailbox *box)
{
	return box->inconsistent;
}
