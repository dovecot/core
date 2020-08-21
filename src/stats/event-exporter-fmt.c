/* Copyright (c) 2019 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "hash.h"
#include "ioloop.h"
#include "event-exporter.h"

void event_export_helper_fmt_unix_time(string_t *dest,
				       const struct timeval *time)
{
	str_printfa(dest, "%"PRIdTIME_T".%06u", time->tv_sec,
		    (unsigned int) time->tv_usec);
}

void event_export_helper_fmt_rfc3339_time(string_t *dest,
					  const struct timeval *time)
{
	const struct tm *tm;

	tm = gmtime(&time->tv_sec);

	str_printfa(dest, "%04d-%02d-%02dT%02d:%02d:%02d.%06luZ",
		    tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
		    tm->tm_hour, tm->tm_min, tm->tm_sec,
		    time->tv_usec);
}

HASH_TABLE_DEFINE_TYPE(category_set, void *, const struct event_category *);

static void insert_category(HASH_TABLE_TYPE(category_set) hash,
			    const struct event_category * const cat)
{
	/* insert this category (key == the unique internal pointer) */
	hash_table_update(hash, cat->internal, cat);

	/* insert parent's categories */
	if (cat->parent != NULL)
		insert_category(hash, cat->parent);
}

void event_export_helper_fmt_categories(string_t *dest,
					struct event_category * const *cats,
					unsigned int count,
					void (*append)(string_t *, const char *),
					const char *separator)
{
	HASH_TABLE_TYPE(category_set) hash;
	struct hash_iterate_context *iter;
	const struct event_category *cat;
	void *key ATTR_UNUSED;
	unsigned int i;
	bool first = TRUE;

	if (count == 0)
		return;

	hash_table_create_direct(&hash, pool_datastack_create(),
				 3 * count /* estimate */);

	/* insert all the categories into the hash table */
	for (i = 0; i < count; i++)
		insert_category(hash, cats[i]);

	/* output each category from hash table */
	iter = hash_table_iterate_init(hash);
	while (hash_table_iterate(iter, hash, &key, &cat)) {
		if (!first)
			str_append(dest, separator);

		append(dest, cat->name);

		first = FALSE;
	}
	hash_table_iterate_deinit(&iter);

	hash_table_destroy(&hash);
}
