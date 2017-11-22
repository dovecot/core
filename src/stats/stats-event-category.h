#ifndef STATS_EVENT_CATEGORY_H
#define STATS_EVENT_CATEGORY_H

/* Register a new event category if it doesn't already exist.
   parent may be NULL. */
void stats_event_category_register(const char *name,
				   struct event_category *parent);

void stats_event_categories_init(void);
void stats_event_categories_deinit(void);

#endif
