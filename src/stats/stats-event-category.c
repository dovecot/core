/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "stats-event-category.h"

static pool_t categories_pool;

void stats_event_category_register(const char *name,
				   struct event_category *parent)
{
	struct event_category *category =
		p_new(categories_pool, struct event_category, 1);
	category->parent = parent;
	category->name = p_strdup(categories_pool, name);

	/* Create a temporary event to register the category. A bit slower
	   than necessary, but this code won't be called often. */
	struct event *event = event_create(NULL);
	struct event_category *categories[] = { category, NULL };
	event_add_categories(event, categories);
	event_unref(&event);
}

void stats_event_categories_init(void)
{
	categories_pool = pool_alloconly_create("categories", 1024);
}

void stats_event_categories_deinit(void)
{
	pool_unref(&categories_pool);
}
