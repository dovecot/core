/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "llist.h"
#include "str.h"
#include "strescape.h"
#include "wildcard-match.h"
#include "lib-event-private.h"
#include "event-filter.h"

enum event_filter_code {
	EVENT_FILTER_CODE_NAME		= 'n',
	EVENT_FILTER_CODE_SOURCE	= 's',
	EVENT_FILTER_CODE_CATEGORY	= 'c',
	EVENT_FILTER_CODE_FIELD		= 'f',
};

struct event_filter_category {
	const char *name;
	/* Pointer to the event_category. NULL if the category isn't
	   registered yet. If it becomes registered, this will be filled out
	   by the category register callback. */
	struct event_category *category;
};

enum event_filter_log_type {
	EVENT_FILTER_LOG_TYPE_DEBUG	= BIT(0),
	EVENT_FILTER_LOG_TYPE_INFO	= BIT(1),
	EVENT_FILTER_LOG_TYPE_WARNING	= BIT(2),
	EVENT_FILTER_LOG_TYPE_ERROR	= BIT(3),
	EVENT_FILTER_LOG_TYPE_FATAL	= BIT(4),
	EVENT_FILTER_LOG_TYPE_PANIC	= BIT(5),

	EVENT_FILTER_LOG_TYPE_ALL	= 0xff,
};
static const char *event_filter_log_type_names[] = {
	"debug", "info", "warning", "error", "fatal", "panic",
};
static enum event_filter_log_type event_filter_log_types[] = {
	EVENT_FILTER_LOG_TYPE_DEBUG,
	EVENT_FILTER_LOG_TYPE_INFO,
	EVENT_FILTER_LOG_TYPE_WARNING,
	EVENT_FILTER_LOG_TYPE_ERROR,
	EVENT_FILTER_LOG_TYPE_FATAL,
	EVENT_FILTER_LOG_TYPE_PANIC,
};

struct event_filter_query_internal {
	unsigned int categories_count;
	unsigned int fields_count;

	bool has_unregistered_categories;
	struct event_filter_category *categories;
	const struct event_field *fields;
	enum event_filter_log_type log_type_mask;

	const char *name;
	const char *source_filename;
	unsigned int source_linenum;

	void *context;
};

struct event_filter {
	struct event_filter *prev, *next;

	pool_t pool;
	int refcount;
	ARRAY(struct event_filter_query_internal) queries;

	bool named_queries_only;
};

static struct event_filter *event_filters = NULL;

struct event_filter *event_filter_create(void)
{
	struct event_filter *filter;
	pool_t pool = pool_alloconly_create("event filter", 2048);

	filter = p_new(pool, struct event_filter, 1);
	filter->pool = pool;
	filter->refcount = 1;
	filter->named_queries_only = TRUE;
	p_array_init(&filter->queries, pool, 4);
	DLLIST_PREPEND(&event_filters, filter);
	return filter;
}

void event_filter_ref(struct event_filter *filter)
{
	i_assert(filter->refcount > 0);
	filter->refcount++;
}

void event_filter_unref(struct event_filter **_filter)
{
	struct event_filter *filter = *_filter;

	if (filter == NULL)
		return;
	i_assert(filter->refcount > 0);

	*_filter = NULL;
	if (--filter->refcount > 0)
		return;

	DLLIST_REMOVE(&event_filters, filter);
	pool_unref(&filter->pool);
}

static bool
event_filter_category_to_log_type(const char *name,
				  enum event_filter_log_type *log_type_r)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(event_filter_log_type_names); i++) {
		if (strcmp(name, event_filter_log_type_names[i]) == 0) {
			*log_type_r = 1 << i;
			return TRUE;
		}
	}
	return FALSE;
}

static void
event_filter_add_categories(struct event_filter *filter,
			    struct event_filter_query_internal *int_query,
			    const char *const *categories)
{
	unsigned int categories_count = str_array_length(categories);
	struct event_filter_category *cat;
	enum event_filter_log_type log_type;
	unsigned int i, j;

	if (categories_count == 0)
		return;

	/* copy strings */
	cat = p_new(filter->pool, struct event_filter_category,
		    categories_count);
	for (i = j = 0; i < categories_count; i++) {
		if (event_filter_category_to_log_type(categories[i], &log_type)) {
			int_query->log_type_mask |= log_type;
			continue;
		}
		cat[j].name = p_strdup(filter->pool, categories[i]);
		cat[j].category = event_category_find_registered(categories[i]);
		if (cat[j].category == NULL)
			int_query->has_unregistered_categories = TRUE;
		j++;
	}
	int_query->categories_count = j;
	int_query->categories = cat;
}

static void
event_filter_add_fields(struct event_filter *filter,
			struct event_filter_query_internal *int_query,
			const struct event_filter_field *fields)
{
	struct event_field *int_fields;
	unsigned int i, count;

	for (count = 0; fields[count].key != NULL; count++) ;
	if (count == 0)
		return;

	int_fields = p_new(filter->pool, struct event_field, count);
	for (i = 0; i < count; i++) {
		int_fields[i].key = p_strdup(filter->pool, fields[i].key);
		/* Filter currently supports only comparing strings
		   and numbers. */
		int_fields[i].value.str = p_strdup(filter->pool, fields[i].value);
		if (str_to_intmax(fields[i].value, &int_fields[i].value.intmax) < 0) {
			/* not a number - no problem */
		}
	}
	int_query->fields_count = count;
	int_query->fields = int_fields;
}

void event_filter_add(struct event_filter *filter,
		      const struct event_filter_query *query)
{
	struct event_filter_query_internal *int_query;

	int_query = array_append_space(&filter->queries);
	int_query->context = query->context;

	if (query->name != NULL)
		int_query->name = p_strdup(filter->pool, query->name);
	else
		filter->named_queries_only = FALSE;

	int_query->source_filename =
		p_strdup_empty(filter->pool, query->source_filename);
	int_query->source_linenum = query->source_linenum;

	if (query->categories != NULL)
		event_filter_add_categories(filter, int_query, query->categories);
	if (query->fields != NULL)
		event_filter_add_fields(filter, int_query, query->fields);

	if (int_query->log_type_mask == 0) {
		/* no explicit log types given. default to all. */
		int_query->log_type_mask = EVENT_FILTER_LOG_TYPE_ALL;
	}
}

void event_filter_merge(struct event_filter *dest,
			const struct event_filter *src)
{
	const struct event_filter_query_internal *int_query;
	struct event_filter_query query;
	unsigned int i;

	array_foreach(&src->queries, int_query) T_BEGIN {
		i_zero(&query);
		query.context = int_query->context;
		query.name = int_query->name;
		query.source_filename = int_query->source_filename;
		query.source_linenum = int_query->source_linenum;

		if (int_query->categories_count > 0 ||
		    int_query->log_type_mask != EVENT_FILTER_LOG_TYPE_ALL) {
			ARRAY_TYPE(const_string) categories;

			t_array_init(&categories, int_query->categories_count);
			for (i = 0; i < int_query->categories_count; i++) {
				array_append(&categories,
					     &int_query->categories[i].name, 1);
			}
			for (i = 0; i < N_ELEMENTS(event_filter_log_type_names); i++) {
				if ((int_query->log_type_mask & (1 << i)) == 0)
					continue;
				array_append(&categories,
					     &event_filter_log_type_names[i], 1);
			}
			array_append_zero(&categories);
			query.categories = array_idx(&categories, 0);
		}
		if (int_query->fields_count > 0) {
			ARRAY(struct event_filter_field) fields;

			t_array_init(&fields, int_query->fields_count);
			for (i = 0; i < int_query->fields_count; i++) {
				struct event_filter_field *field =
					array_append_space(&fields);
				field->key = p_strdup(dest->pool, int_query->fields[i].key);
				field->value = p_strdup(dest->pool, int_query->fields[i].value.str);
			}
			array_append_zero(&fields);
			query.fields = array_idx(&fields, 0);
		}

		event_filter_add(dest, &query);
	} T_END;
}

static void
event_filter_export_query(const struct event_filter_query_internal *query,
			  string_t *dest)
{
	unsigned int i;

	if (query->name != NULL) {
		str_append_c(dest, EVENT_FILTER_CODE_NAME);
		str_append_tabescaped(dest, query->name);
		str_append_c(dest, '\t');
	}
	if (query->source_filename != NULL) {
		str_append_c(dest, EVENT_FILTER_CODE_SOURCE);
		str_append_tabescaped(dest, query->source_filename);
		str_printfa(dest, "\t%u\t", query->source_linenum);
	}
	for (i = 0; i < query->categories_count; i++) {
		str_append_c(dest, EVENT_FILTER_CODE_CATEGORY);
		str_append_tabescaped(dest, query->categories[i].name);
		str_append_c(dest, '\t');
	}
	if (query->log_type_mask != EVENT_FILTER_LOG_TYPE_ALL) {
		for (i = 0; i < N_ELEMENTS(event_filter_log_type_names); i++) {
			if ((query->log_type_mask & (1 << i)) == 0)
				continue;
			str_append_c(dest, EVENT_FILTER_CODE_CATEGORY);
			str_append_tabescaped(dest, event_filter_log_type_names[i]);
			str_append_c(dest, '\t');
		}
	}

	for (i = 0; i < query->fields_count; i++) {
		str_append_c(dest, EVENT_FILTER_CODE_FIELD);
		str_append_tabescaped(dest, query->fields[i].key);
		str_append_c(dest, '\t');
		str_append_tabescaped(dest, query->fields[i].value.str);
		str_append_c(dest, '\t');
	}
}

void event_filter_export(struct event_filter *filter, string_t *dest)
{
	const struct event_filter_query_internal *query;
	bool first = TRUE;

	array_foreach(&filter->queries, query) {
		if (!first)
			str_append_c(dest, '\t');
		first = FALSE;
		event_filter_export_query(query, dest);
	}
}

bool event_filter_import(struct event_filter *filter, const char *str,
			 const char **error_r)
{
	return event_filter_import_unescaped(filter,
		t_strsplit_tabescaped(str), error_r);
}

bool event_filter_import_unescaped(struct event_filter *filter,
				   const char *const *args,
				   const char **error_r)
{
	struct event_filter_query query;
	ARRAY_TYPE(const_string) categories;
	ARRAY(struct event_filter_field) fields;
	bool changed;

	t_array_init(&categories, 8);
	t_array_init(&fields, 8);
	i_zero(&query);
	changed = FALSE;
	for (unsigned int i = 0; args[i] != NULL; i++) {
		const char *arg = args[i];

		if (arg[0] == '\0') {
			/* finish the query */
			if (array_count(&categories) > 0) {
				array_append_zero(&categories);
				query.categories = array_idx(&categories, 0);
			}
			if (array_count(&fields) > 0) {
				array_append_zero(&fields);
				query.fields = array_idx(&fields, 0);
			}
			event_filter_add(filter, &query);

			/* start the next query */
			i_zero(&query);
			array_clear(&categories);
			array_clear(&fields);
			changed = FALSE;
			continue;
		}

		enum event_filter_code code = arg[0];
		arg++;
		switch (code) {
		case EVENT_FILTER_CODE_NAME:
			query.name = arg;
			break;
		case EVENT_FILTER_CODE_SOURCE:
			query.source_filename = arg;
			i++;
			if (args[i] == NULL) {
				*error_r = "Source line number missing";
				return FALSE;
			}
			if (str_to_uint(args[i], &query.source_linenum) < 0) {
				*error_r = "Invalid Source line number";
				return FALSE;
			}
			break;
		case EVENT_FILTER_CODE_CATEGORY:
			array_append(&categories, &arg, 1);
			break;
		case EVENT_FILTER_CODE_FIELD: {
			struct event_filter_field *field;

			field = array_append_space(&fields);
			field->key = arg;
			i++;
			if (args[i] == NULL) {
				*error_r = "Field value missing";
				return FALSE;
			}
			field->value = args[i];
			break;
		}
		}
		changed = TRUE;
	}
	if (changed) {
		*error_r = "Expected TAB at the end";
		return FALSE;
	}
	return TRUE;
}

static bool
event_has_category(struct event *event, struct event_category *wanted_category)
{
	struct event_category *const *catp;

	i_assert(wanted_category != NULL);

	while (event != NULL) {
		if (array_is_created(&event->categories)) {
			array_foreach(&event->categories, catp) {
				if (*catp == wanted_category)
					return TRUE;
			}
		}
		/* try also the parent events */
		event = event_get_parent(event);
	}
	return FALSE;
}

static bool
event_filter_query_match_categories(const struct event_filter_query_internal *query,
				    struct event *event)
{
	if (query->has_unregistered_categories) {
		/* At least one of the categories in the filter hasn't even
		   been registered yet. This filter can't match. */
		return FALSE;
	}

	for (unsigned int i = 0; i < query->categories_count; i++) {
		if (!event_has_category(event, query->categories[i].category))
			return FALSE;
	}
	return TRUE;
}

static bool
event_match_field(struct event *event, const struct event_field *wanted_field)
{
	const struct event_field *field;

	/* wanted_field has the value in all available formats */
	while ((field = event_find_field(event, wanted_field->key)) == NULL) {
		event = event_get_parent(event);
		if (event == NULL)
			return FALSE;
	}
	switch (field->value_type) {
	case EVENT_FIELD_VALUE_TYPE_STR:
		return wildcard_match_icase(field->value.str, wanted_field->value.str);
	case EVENT_FIELD_VALUE_TYPE_INTMAX:
		return field->value.intmax == wanted_field->value.intmax;
	case EVENT_FIELD_VALUE_TYPE_TIMEVAL:
		/* there's no point to support matching exact timestamps */
		return FALSE;
	}
	i_unreached();
}

static bool
event_filter_query_match_fields(const struct event_filter_query_internal *query,
				struct event *event)
{
	for (unsigned int i = 0; i < query->fields_count; i++) {
		if (!event_match_field(event, &query->fields[i]))
			return FALSE;
	}
	return TRUE;
}

static bool
event_filter_query_match(const struct event_filter_query_internal *query,
			 struct event *event, const char *source_filename,
			 unsigned int source_linenum,
			 const struct failure_context *ctx)
{
	i_assert(ctx->type < N_ELEMENTS(event_filter_log_types));
	if ((query->log_type_mask & event_filter_log_types[ctx->type]) == 0)
		return FALSE;

	if (query->name != NULL) {
		if (event->sending_name == NULL ||
		    strcmp(event->sending_name, query->name) != 0)
			return FALSE;
	}
	if (query->source_filename != NULL) {
		if (source_linenum != query->source_linenum ||
		    source_filename == NULL ||
		    strcmp(event->source_filename, query->source_filename) != 0)
			return FALSE;
	}
	if (!event_filter_query_match_categories(query, event))
		return FALSE;
	if (!event_filter_query_match_fields(query, event))
		return FALSE;
	return TRUE;
}

static bool
event_filter_match_fastpath(struct event_filter *filter, struct event *event)
{
	if (filter->named_queries_only && event->sending_name == NULL) {
		/* No debug logging is enabled. Only named events may be wanted
		   for stats. This event doesn't have a name, so we don't need
		   to check any further. */
		return FALSE;
	}
	return TRUE;
}

bool event_filter_match(struct event_filter *filter, struct event *event,
			const struct failure_context *ctx)
{
	return event_filter_match_source(filter, event, event->source_filename,
					 event->source_linenum, ctx);
}

bool event_filter_match_source(struct event_filter *filter, struct event *event,
			       const char *source_filename,
			       unsigned int source_linenum,
			       const struct failure_context *ctx)
{
	const struct event_filter_query_internal *query;

	if (!event_filter_match_fastpath(filter, event))
		return FALSE;

	array_foreach(&filter->queries, query) {
		if (event_filter_query_match(query, event, source_filename,
					     source_linenum, ctx))
			return TRUE;
	}
	return FALSE;
}

struct event_filter_match_iter {
	struct event_filter *filter;
	struct event *event;
	const struct failure_context *failure_ctx;
	unsigned int idx;
};

struct event_filter_match_iter *
event_filter_match_iter_init(struct event_filter *filter, struct event *event,
			     const struct failure_context *ctx)
{
	struct event_filter_match_iter *iter;

	iter = i_new(struct event_filter_match_iter, 1);
	iter->filter = filter;
	iter->event = event;
	iter->failure_ctx = ctx;
	if (!event_filter_match_fastpath(filter, event))
		iter->idx = UINT_MAX;
	return iter;
}

void *event_filter_match_iter_next(struct event_filter_match_iter *iter)
{
	const struct event_filter_query_internal *queries;
	unsigned int count;

	queries = array_get(&iter->filter->queries, &count);
	while (iter->idx < count) {
		const struct event_filter_query_internal *query =
			&queries[iter->idx];

		iter->idx++;
		if (query->context != NULL &&
		    event_filter_query_match(query, iter->event,
					     iter->event->source_filename,
					     iter->event->source_linenum,
					     iter->failure_ctx))
			return query->context;
	}
	return NULL;
}

void event_filter_match_iter_deinit(struct event_filter_match_iter **_iter)
{
	struct event_filter_match_iter *iter = *_iter;

	*_iter = NULL;
	i_free(iter);
}

static void
event_filter_query_remove_category(struct event_filter_query_internal *query,
				   struct event_category *category)
{
	for (unsigned int i = 0; i < query->categories_count; i++) {
		if (query->categories[i].category == category) {
			query->categories[i].category = NULL;
			query->has_unregistered_categories = TRUE;
		}
	}
}

static void
event_filter_remove_category(struct event_filter *filter,
			     struct event_category *category)
{
	struct event_filter_query_internal *query;

	array_foreach_modifiable(&filter->queries, query)
		event_filter_query_remove_category(query, category);
}

static void
event_filter_query_add_missing_category(struct event_filter_query_internal *query,
					struct event_category *category)
{
	if (!query->has_unregistered_categories)
		return;
	query->has_unregistered_categories = FALSE;

	for (unsigned int i = 0; i < query->categories_count; i++) {
		if (query->categories[i].category != NULL)
			continue;

		if (strcmp(query->categories[i].name, category->name) == 0)
			query->categories[i].category = category;
		else
			query->has_unregistered_categories = TRUE;
	}
}

static void
event_filter_add_missing_category(struct event_filter *filter,
				  struct event_category *category)
{
	struct event_filter_query_internal *query;

	array_foreach_modifiable(&filter->queries, query)
		event_filter_query_add_missing_category(query, category);
}

static void event_filter_category_registered(struct event_category *category)
{
	struct event_filter *filter;

	for (filter = event_filters; filter != NULL; filter = filter->next) {
		if (!category->registered)
			event_filter_remove_category(filter, category);
		else
			event_filter_add_missing_category(filter, category);
	}
}

void event_filter_init(void)
{
	event_category_register_callback(event_filter_category_registered);
}

void event_filter_deinit(void)
{
	event_category_unregister_callback(event_filter_category_registered);
}
