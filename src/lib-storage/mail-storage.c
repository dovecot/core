/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "mail-storage.h"

#include <stdlib.h>
#include <time.h>
#include <ctype.h>

/* Message to show to users when critical error occurs */
#define CRITICAL_MSG "Internal error [%Y-%m-%d %H:%M:%S]"

struct mail_storage_list {
	struct mail_storage_list *next;
	struct mail_storage *storage;
};

struct client_workaround_list {
	const char *name;
	enum client_workarounds num;
};

struct client_workaround_list client_workaround_list[] = {
	{ "oe6-fetch-no-newmail", WORKAROUND_OE6_FETCH_NO_NEWMAIL },
	{ "oe6-fetch-redundant-msgset", WORKAROUND_OE6_FETCH_REDUNDANT_MSGSET },
	{ "outlook-idle", WORKAROUND_OUTLOOK_IDLE },
	{ NULL, 0 }
};

static struct mail_storage_list *storages = NULL;
enum client_workarounds client_workarounds = 0;
int full_filesystem_access = FALSE;

void mail_storage_init(void)
{
        struct client_workaround_list *list;
	const char *env;
	const char *const *str;

        full_filesystem_access = getenv("FULL_FILESYSTEM_ACCESS") != NULL;

	env = getenv("CLIENT_WORKAROUNDS");
	if (env == NULL)
		return;

	for (str = t_strsplit(env, " "); *str != NULL; str++) {
		if (**str == '\0')
			continue;

		list = client_workaround_list;
		for (; list->name != NULL; list++) {
			if (strcasecmp(*str, list->name) == 0) {
				client_workarounds |= list->num;
				break;
			}
		}
		if (list->name == NULL)
			i_fatal("Unknown client workaround: %s", *str);
	}
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

			(*list)->storage->free((*list)->storage);
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

	storage->free(storage);
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
	storage->error = strftime(str, sizeof(str), CRITICAL_MSG, tm) > 0 ?
		i_strdup(str) : i_strdup("Internal error");
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

const char *mail_storage_get_last_error(struct mail_storage *storage,
					int *syntax)
{
	if (syntax != NULL)
		*syntax = storage->syntax_error;
	return storage->error;
}
