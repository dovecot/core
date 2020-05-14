/* Copyright (c) 2020 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "lib-event-private.h"
#include "event-filter.h"

static void add_category(ARRAY_TYPE(const_string) *categories, const char *name)
{
	if (!array_is_created(categories))
		t_array_init(categories, 4);
	array_push_back(categories, &name);
}

static int parse_query(const char *str, struct event_filter_query *query_r,
		       const char **error_r)
{
	ARRAY_TYPE(const_string) categories = ARRAY_INIT;
	ARRAY(struct event_filter_field) fields = ARRAY_INIT;

	i_zero(query_r);
	do {
		while (*str == ' ')
			str++;
		const char *p = strchr(str, ' ');
		if (p != NULL)
			str = t_strdup_until(str, p++);

		if (strncmp(str, "event:", 6) == 0) {
			query_r->name = str+6;
		} else if (strncmp(str, "source:", 7) == 0) {
			const char *linep = strchr(str+7, ':');
			if (linep == NULL) {
				/* filename only - match to all line numbers */
				query_r->source_filename = str+7;
			} else {
				query_r->source_filename = t_strdup_until(str+7, linep);
				if (str_to_uint(linep+1, &query_r->source_linenum) < 0) {
					*error_r = t_strdup_printf(
						"Invalid line number in '%s'", str);
					return -1;
				}
			}
		} else if (strncmp(str, "field:", 6) == 0) {
			const char *value = strchr(str+6, '=');
			if (value == NULL) {
				*error_r = t_strdup_printf(
					"Missing '=' in '%s'", str);
				return -1;
			}
			if (!array_is_created(&fields))
				t_array_init(&fields, 4);
			struct event_filter_field *field =
				array_append_space(&fields);
			field->key = t_strdup_until(str+6, value);
			field->value = value+1;
		} else if (str_begins(str, "cat:"))
			add_category(&categories, str+4);
		else if (str_begins(str, "category:"))
			add_category(&categories, str+9);
		else if (str_begins(str, "service:")) {
			/* service:name is short for category:service:name */
			add_category(&categories, str);
		} else {
			*error_r = t_strdup_printf("Unknown event '%s'", str);
			return -1;
		}
		str = p;
	} while (str != NULL);

	if (array_is_created(&categories)) {
		array_append_zero(&categories);
		query_r->categories = array_front(&categories);
	}
	if (array_is_created(&fields)) {
		array_append_zero(&fields);
		query_r->fields = array_front(&fields);
	}
	return 0;
}

int event_filter_parse(const char *str, struct event_filter *filter,
		       const char **error_r)
{
	struct event_filter_query query;
	const char *p;

	while (*str != '\0') {
		if (*str == ' ') {
			str++;
			continue;
		}

		if (*str == '(') {
			/* everything inside (...) is a single query */
			str++;
			p = strchr(str, ')');
			if (p == NULL) {
				*error_r = "Missing ')'";
				return -1;
			}
			if (parse_query(t_strdup_until(str, p), &query, error_r) < 0)
				return -1;
			str = p+1;
		} else if ((p = strchr(str, ' ')) != NULL) {
			/* parse a single-word query in the middle */
			if (parse_query(t_strdup_until(str, p), &query, error_r) < 0)
				return -1;
			str = p+1;
		} else {
			/* single-word last query */
			if (parse_query(str, &query, error_r) < 0)
				return -1;
			str = "";
		}

		event_filter_add(filter, &query);
	}

	*error_r = NULL;

	return 0;
}
