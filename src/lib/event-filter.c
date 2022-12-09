/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "llist.h"
#include "str.h"
#include "strescape.h"
#include "wildcard-match.h"
#include "lib-event-private.h"
#include "event-filter.h"
#include "event-filter-private.h"

/* Note: this has to match the regexp behavior in the event filter lexer file */
#define event_filter_append_escaped(dst, str) \
	str_append_escaped((dst), (str), strlen(str))

enum event_filter_code {
	EVENT_FILTER_CODE_NAME		= 'n',
	EVENT_FILTER_CODE_SOURCE	= 's',
	EVENT_FILTER_CODE_CATEGORY	= 'c',
	EVENT_FILTER_CODE_FIELD		= 'f',
};

/* map <log type> to <event filter log type & name> */
static const struct log_type_map {
	enum event_filter_log_type log_type;
	const char *name;
} event_filter_log_type_map[] = {
	[LOG_TYPE_DEBUG]   = { EVENT_FILTER_LOG_TYPE_DEBUG, "debug" },
	[LOG_TYPE_INFO]    = { EVENT_FILTER_LOG_TYPE_INFO, "info" },
	[LOG_TYPE_WARNING] = { EVENT_FILTER_LOG_TYPE_WARNING, "warning" },
	[LOG_TYPE_ERROR]   = { EVENT_FILTER_LOG_TYPE_ERROR, "error" },
	[LOG_TYPE_FATAL]   = { EVENT_FILTER_LOG_TYPE_FATAL, "fatal" },
	[LOG_TYPE_PANIC]   = { EVENT_FILTER_LOG_TYPE_PANIC, "panic" },
};
static_assert_array_size(event_filter_log_type_map, LOG_TYPE_COUNT);

struct event_filter_query_internal {
	struct event_filter_node *expr;
	void *context;
};

static struct event_filter *event_filters = NULL;

static struct event_filter *event_filter_create_real(pool_t pool, bool fragment)
{
	struct event_filter *filter;

	filter = p_new(pool, struct event_filter, 1);
	filter->pool = pool;
	filter->refcount = 1;
	filter->named_queries_only = TRUE;
	filter->fragment = fragment;
	p_array_init(&filter->queries, pool, 4);
	if (!fragment)
		DLLIST_PREPEND(&event_filters, filter);
	return filter;
}

struct event_filter *event_filter_create(void)
{
	return event_filter_create_real(pool_alloconly_create("event filter", 2048), FALSE);
}

struct event_filter *event_filter_create_fragment(pool_t pool)
{
	return event_filter_create_real(pool, TRUE);
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

	if (!filter->fragment) {
		DLLIST_REMOVE(&event_filters, filter);

		/* fragments' pools are freed by the consumer */
		pool_unref(&filter->pool);
	}
}

/*
 * Look for an existing query with the same context pointer and return it.
 *
 * If not found, allocate a new internal query and return it.
 */
static struct event_filter_query_internal *
event_filter_get_or_alloc_internal_query(struct event_filter *filter,
					 void *context)
{
	struct event_filter_query_internal *query;

	array_foreach_modifiable(&filter->queries, query) {
		if (query->context == context)
			return query;
	}

	/* no matching context, allocate a new query */
	query = array_append_space(&filter->queries);
	query->context = context;
	query->expr = NULL;

	return query;
}

static void add_node(pool_t pool, struct event_filter_node **root,
		     struct event_filter_node *new,
		     enum event_filter_node_op op)
{
	struct event_filter_node *parent;

	i_assert((op == EVENT_FILTER_OP_AND) || (op == EVENT_FILTER_OP_OR));

	if (*root == NULL) {
		*root = new;
		return;
	}

	parent = p_new(pool, struct event_filter_node, 1);
	parent->type = EVENT_FILTER_NODE_TYPE_LOGIC;
	parent->op = op;
	parent->children[0] = *root;
	parent->children[1] = new;

	*root = parent;
}

static bool filter_node_requires_event_name(struct event_filter_node *node)
{
	switch (node->op) {
	case EVENT_FILTER_OP_NOT:
		return filter_node_requires_event_name(node->children[0]);
	case EVENT_FILTER_OP_AND:
		return filter_node_requires_event_name(node->children[0]) ||
			filter_node_requires_event_name(node->children[1]);
	case EVENT_FILTER_OP_OR:
		return filter_node_requires_event_name(node->children[0]) &&
			filter_node_requires_event_name(node->children[1]);
	default:
		return node->type == EVENT_FILTER_NODE_TYPE_EVENT_NAME_WILDCARD ||
			node->type == EVENT_FILTER_NODE_TYPE_EVENT_NAME_EXACT;
	}
}

int event_filter_parse(const char *str, struct event_filter *filter,
		       const char **error_r)
{
	struct event_filter_query_internal *int_query;
	struct event_filter_parser_state state;
	int ret;

	i_zero(&state);
	state.input = str;
	state.len = strlen(str);
	state.pos = 0;
	state.pool = filter->pool;

	event_filter_parser_lex_init(&state.scanner);
	event_filter_parser_set_extra(&state, state.scanner);

	ret = event_filter_parser_parse(&state);

	event_filter_parser_lex_destroy(state.scanner);

	if ((ret == 0) && (state.output != NULL)) {
		/* success - non-NULL expression */
		i_assert(state.error == NULL);

		int_query = event_filter_get_or_alloc_internal_query(filter, NULL);

		add_node(filter->pool, &int_query->expr, state.output,
			 EVENT_FILTER_OP_OR);

		filter->named_queries_only = filter->named_queries_only &&
			filter_node_requires_event_name(state.output);
	} else if (ret != 0) {
		/* error */
		i_assert(state.error != NULL);

		*error_r = state.error;
	}

	/*
	 * Note that success with a NULL expression output is possible, but
	 * turns into a no-op.
	 */

	return (ret != 0) ? -1 : 0;
}

bool event_filter_category_to_log_type(const char *name,
				       enum event_filter_log_type *log_type_r)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(event_filter_log_type_map); i++) {
		if (strcmp(name, event_filter_log_type_map[i].name) == 0) {
			*log_type_r = event_filter_log_type_map[i].log_type;
			return TRUE;
		}
	}
	return FALSE;
}

const char *
event_filter_category_from_log_type(enum event_filter_log_type log_type)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(event_filter_log_type_map); i++) {
		if (event_filter_log_type_map[i].log_type == log_type)
			return event_filter_log_type_map[i].name;
	}
	i_unreached();
}

static struct event_filter_node *
clone_expr(pool_t pool, struct event_filter_node *old)
{
	struct event_filter_node *new;

	if (old == NULL)
		return NULL;

	new = p_new(pool, struct event_filter_node, 1);
	new->type = old->type;
	new->op = old->op;
	new->children[0] = clone_expr(pool, old->children[0]);
	new->children[1] = clone_expr(pool, old->children[1]);
	new->str = p_strdup(pool, old->str);
	new->intmax = old->intmax;
	new->category.log_type = old->category.log_type;
	new->category.name = p_strdup(pool, old->category.name);
	new->category.ptr = old->category.ptr;
	new->field.key = p_strdup(pool, old->field.key);
	new->field.value_type = old->field.value_type;
	new->field.value.str = p_strdup(pool, old->field.value.str);
	new->field.value.intmax = old->field.value.intmax;
	new->field.value.timeval = old->field.value.timeval;
	new->ambiguous_unit = old->ambiguous_unit;
	new->warned_ambiguous_unit = old->warned_ambiguous_unit;
	new->warned_type_mismatch = old->warned_type_mismatch;
	new->warned_string_inequality = old->warned_string_inequality;
	new->warned_timeval_not_implemented = old->warned_timeval_not_implemented;

	return new;
}

static void
event_filter_merge_with_context_internal(struct event_filter *dest,
					 const struct event_filter *src,
					 void *new_context, bool with_context)
{
	const struct event_filter_query_internal *int_query;

	array_foreach(&src->queries, int_query) T_BEGIN {
		void *context = with_context ? new_context : int_query->context;
		struct event_filter_query_internal *new;

		new = event_filter_get_or_alloc_internal_query(dest, context);

		add_node(dest->pool, &new->expr,
			 clone_expr(dest->pool, int_query->expr),
			 EVENT_FILTER_OP_OR);
	} T_END;
}

bool event_filter_remove_queries_with_context(struct event_filter *filter,
					      void *context)
{
	const struct event_filter_query_internal *int_query;
	unsigned int idx;

	array_foreach(&filter->queries, int_query) {
		if (int_query->context == context) {
			idx = array_foreach_idx(&filter->queries, int_query);
			array_delete(&filter->queries, idx, 1);
			return TRUE;
		}
	}
	return FALSE;
}

void event_filter_merge(struct event_filter *dest,
			const struct event_filter *src)
{
	event_filter_merge_with_context_internal(dest, src, NULL, FALSE);
}

void event_filter_merge_with_context(struct event_filter *dest,
				     const struct event_filter *src,
				     void *new_context)
{
	event_filter_merge_with_context_internal(dest, src, new_context, TRUE);
}

static const char *
event_filter_export_query_expr_op(enum event_filter_node_op op)
{
	switch (op) {
	case EVENT_FILTER_OP_AND:
	case EVENT_FILTER_OP_OR:
	case EVENT_FILTER_OP_NOT:
		i_unreached();
	case EVENT_FILTER_OP_CMP_EQ:
		return "=";
	case EVENT_FILTER_OP_CMP_GT:
		return ">";
	case EVENT_FILTER_OP_CMP_LT:
		return "<";
	case EVENT_FILTER_OP_CMP_GE:
		return ">=";
	case EVENT_FILTER_OP_CMP_LE:
		return "<=";
	}

	i_unreached();
}

static void
event_filter_export_query_expr(const struct event_filter_query_internal *query,
			       struct event_filter_node *node,
			       string_t *dest)
{
	switch (node->type) {
	case EVENT_FILTER_NODE_TYPE_LOGIC:
		str_append_c(dest, '(');
		switch (node->op) {
		case EVENT_FILTER_OP_AND:
			event_filter_export_query_expr(query, node->children[0], dest);
			str_append(dest, " AND ");
			event_filter_export_query_expr(query, node->children[1], dest);
			break;
		case EVENT_FILTER_OP_OR:
			event_filter_export_query_expr(query, node->children[0], dest);
			str_append(dest, " OR ");
			event_filter_export_query_expr(query, node->children[1], dest);
			break;
		case EVENT_FILTER_OP_NOT:
			str_append(dest, "NOT ");
			event_filter_export_query_expr(query, node->children[0], dest);
			break;
		case EVENT_FILTER_OP_CMP_EQ:
		case EVENT_FILTER_OP_CMP_GT:
		case EVENT_FILTER_OP_CMP_LT:
		case EVENT_FILTER_OP_CMP_GE:
		case EVENT_FILTER_OP_CMP_LE:
			i_unreached();
		}
		str_append_c(dest, ')');
		break;
	case EVENT_FILTER_NODE_TYPE_EVENT_NAME_EXACT:
	case EVENT_FILTER_NODE_TYPE_EVENT_NAME_WILDCARD:
		str_append(dest, "event");
		str_append(dest, event_filter_export_query_expr_op(node->op));
		str_append_c(dest, '"');
		event_filter_append_escaped(dest, node->str);
		str_append_c(dest, '"');
		break;
	case EVENT_FILTER_NODE_TYPE_EVENT_SOURCE_LOCATION:
		str_append(dest, "source_location");
		str_append(dest, event_filter_export_query_expr_op(node->op));
		str_append_c(dest, '"');
		event_filter_append_escaped(dest, node->str);
		if (node->intmax != 0)
			str_printfa(dest, ":%ju", node->intmax);
		str_append_c(dest, '"');
		break;
	case EVENT_FILTER_NODE_TYPE_EVENT_CATEGORY:
		str_append(dest, "category");
		str_append(dest, event_filter_export_query_expr_op(node->op));
		if (node->category.name != NULL) {
			str_append_c(dest, '"');
			event_filter_append_escaped(dest, node->category.name);
			str_append_c(dest, '"');
		} else
			str_append(dest, event_filter_category_from_log_type(node->category.log_type));
		break;
	case EVENT_FILTER_NODE_TYPE_EVENT_FIELD_EXACT:
	case EVENT_FILTER_NODE_TYPE_EVENT_FIELD_WILDCARD:
	case EVENT_FILTER_NODE_TYPE_EVENT_FIELD_NUMERIC_WILDCARD:
		str_append_c(dest, '"');
		event_filter_append_escaped(dest, node->field.key);
		str_append_c(dest, '"');
		str_append(dest, event_filter_export_query_expr_op(node->op));
		str_append_c(dest, '"');
		event_filter_append_escaped(dest, node->field.value.str);
		str_append_c(dest, '"');
		break;
	}
}

static void
event_filter_export_query(const struct event_filter_query_internal *query,
			  string_t *dest)
{
	str_append_c(dest, '(');
	event_filter_export_query_expr(query, query->expr, dest);
	str_append_c(dest, ')');
}

void event_filter_export(struct event_filter *filter, string_t *dest)
{
	const struct event_filter_query_internal *query;
	bool first = TRUE;

	array_foreach(&filter->queries, query) {
		if (!first)
			str_append(dest, " OR ");
		first = FALSE;
		event_filter_export_query(query, dest);
	}
}

struct event_filter_node *
event_filter_get_expr_for_testing(struct event_filter *filter,
				  unsigned int *count_r)
{
	const struct event_filter_query_internal *queries;

	queries = array_get(&filter->queries, count_r);

	return (*count_r == 0) ? NULL : queries[0].expr;
}

static bool
event_category_match(const struct event_category *category,
		     const struct event_category *wanted_category)
{
	for (; category != NULL; category = category->parent) {
		if (category->internal == wanted_category->internal)
			return TRUE;
	}
	return FALSE;
}

static bool
event_has_category_nonrecursive(struct event *event,
				struct event_category *wanted_category)
{
	struct event_category *cat;

	if (array_is_created(&event->categories)) {
		array_foreach_elem(&event->categories, cat) {
			if (event_category_match(cat, wanted_category))
				return TRUE;
		}
	}
	return FALSE;
}

static bool
event_has_category(struct event *event, struct event_filter_node *node,
		   enum event_filter_log_type log_type)
{
	struct event_category *wanted_category = node->category.ptr;

	/* category is a log type */
	if (node->category.name == NULL)
		return (node->category.log_type & log_type) != 0;

	/* category not registered, therefore the event cannot have it */
	if (wanted_category == NULL)
		return FALSE;

	while (event != NULL) {
		if (event_has_category_nonrecursive(event, wanted_category))
			return TRUE;
		/* try also the parent events */
		event = event_get_parent(event);
	}
	/* check also the global event and its parents */
	event = event_get_global();
	while (event != NULL) {
		if (event_has_category_nonrecursive(event, wanted_category))
			return TRUE;
		event = event_get_parent(event);
	}
	return FALSE;
}

static bool
event_match_strlist_recursive(struct event *event,
			      const struct event_field *wanted_field,
			      bool use_strcmp, bool *seen)
{
	const char *wanted_value = wanted_field->value.str;
	const struct event_field *field;
	const char *value;
	bool match;

	if (event == NULL)
		return FALSE;

	field = event_find_field_nonrecursive(event, wanted_field->key);
	if (field != NULL) {
		i_assert(field->value_type == EVENT_FIELD_VALUE_TYPE_STRLIST);
		array_foreach_elem(&field->value.strlist, value) {
			*seen = TRUE;
			match = use_strcmp ? strcmp(value, wanted_value) == 0 :
				wildcard_match_icase(value, wanted_value);
			if (match)
				return TRUE;
		}
	}
	return event_match_strlist_recursive(event->parent, wanted_field,
					     use_strcmp, seen);
}

static bool
event_match_strlist(struct event *event, const struct event_field *wanted_field,
		    bool use_strcmp)
{
	bool seen = FALSE;

	if (event_match_strlist_recursive(event, wanted_field,
					  use_strcmp, &seen))
		return TRUE;
	if (event_match_strlist_recursive(event_get_global(),
					  wanted_field, use_strcmp, &seen))
		return TRUE;
	if (wanted_field->value.str[0] == '\0' && !seen) {
		/* strlist="" matches nonexistent strlist */
		return TRUE;
	}
	return FALSE;

}

static bool
event_filter_handle_numeric_operation(enum event_filter_node_op op,
				      intmax_t a, intmax_t b)
{
	switch (op) {
	case EVENT_FILTER_OP_CMP_EQ:
		return a == b;
	case EVENT_FILTER_OP_CMP_GT:
		return a > b;
	case EVENT_FILTER_OP_CMP_LT:
		return a < b;
	case EVENT_FILTER_OP_CMP_GE:
		return a >= b;
	case EVENT_FILTER_OP_CMP_LE:
		return a <= b;
	case EVENT_FILTER_OP_AND:
	case EVENT_FILTER_OP_OR:
	case EVENT_FILTER_OP_NOT:
		i_unreached();
	}
	i_unreached();
}

static bool
event_match_field(struct event *event, struct event_filter_node *node,
		  bool use_strcmp, const char *source_filename,
		  unsigned int source_linenum)
{
	const struct event_field *field;
	struct event_field duration;

	const struct event_field *wanted_field = &node->field;
	if (strcmp(wanted_field->key, "duration") == 0) {
		uintmax_t duration_value;
		i_zero(&duration);
		duration.key = "duration";
		duration.value_type = EVENT_FIELD_VALUE_TYPE_INTMAX;
		event_get_last_duration(event, &duration_value);
		duration.value.intmax = (intmax_t)duration_value;
		field = &duration;
	} else {
		/* wanted_field has the value in all available formats */
		field = event_find_field_recursive(event, wanted_field->key);
	}
	if (field == NULL) {
		/* field="" matches nonexistent field */
		return wanted_field->value.str[0] == '\0';
	}

	switch (field->value_type) {
	case EVENT_FIELD_VALUE_TYPE_STR:
		/* We only support string equality comparisons. */
		if (node->op != EVENT_FILTER_OP_CMP_EQ) {
			/* Warn about non-equality comparisons. */
			if (!node->warned_string_inequality) {
				const char *name = event->sending_name;
				/* Use i_warning to prevent event filter recursions. */
				i_warning("Event filter for string field '%s' "
					  "only supports equality operation "
					  "'=' not '%s'. (event=%s, source=%s:%u)",
					  wanted_field->key,
					  event_filter_export_query_expr_op(node->op),
					  name != NULL ? name : "",
					  source_filename, source_linenum);
				node->warned_string_inequality = TRUE;
			}
			return FALSE;
		}
		if (field->value.str[0] == '\0') {
			/* field was removed, but it matches field="" filter */
			return wanted_field->value.str[0] == '\0';
		}
		if (use_strcmp)
			return strcasecmp(field->value.str, wanted_field->value.str) == 0;
		else
			return wildcard_match_icase(field->value.str, wanted_field->value.str);
	case EVENT_FIELD_VALUE_TYPE_INTMAX:
		if (node->ambiguous_unit) {
			if (!node->warned_ambiguous_unit) {
				const char *name = event->sending_name;
				/* Use i_warning to prevent event filter recursions. */
				i_warning("Event filter matches integer field "
					  "'%s' with value that has an "
					  "ambiguous unit '%s'. Please use "
					  "either 'mins' or 'MB' to specify "
					  "interval or size respectively. "
					  "(event=%s, source=%s:%u)",
					  wanted_field->key,
					  wanted_field->value.str,
					  name != NULL ? name : "",
					  source_filename, source_linenum);
				node->warned_ambiguous_unit = TRUE;
			}
			return FALSE;
		} else if (wanted_field->value_type == EVENT_FIELD_VALUE_TYPE_INTMAX) {
			/* compare against an integer */
			return event_filter_handle_numeric_operation(
				node->op, field->value.intmax, wanted_field->value.intmax);
		} else if (use_strcmp ||
			   (node->type != EVENT_FILTER_NODE_TYPE_EVENT_FIELD_NUMERIC_WILDCARD)) {
			if (!node->warned_type_mismatch) {
				const char *name = event->sending_name;
				/* Use i_warning to prevent event filter recursions. */
				i_warning("Event filter matches integer field "
					  "'%s' against non-integer value '%s'. "
					  "(event=%s, source=%s:%u)",
					  wanted_field->key,
					  wanted_field->value.str,
					  name != NULL ? name : "",
					  source_filename, source_linenum);
				node->warned_type_mismatch = TRUE;
			}
			return FALSE;
		} else if (node->op != EVENT_FILTER_OP_CMP_EQ) {
			/* In this branch a numeric value is matched against a
			   wildcard, which requires an equality operation. */
			if (!node->warned_type_mismatch) {
				const char *name = event->sending_name;
				/* Use i_warning to prevent event filter recursions. */
				i_warning("Event filter matches integer field "
					  "'%s' against wildcard value '%s' "
					  "with an incompatible operation '%s', "
					  "please use '='. (event=%s, "
					  "source=%s:%u)",
					  wanted_field->key,
					  wanted_field->value.str,
					  event_filter_export_query_expr_op(node->op),
					  name != NULL ? name : "",
					  source_filename, source_linenum);
				node->warned_type_mismatch = TRUE;
			}
			return FALSE;
		} else {
			char tmp[MAX_INT_STRLEN];
			i_snprintf(tmp, sizeof(tmp), "%jd", field->value.intmax);
			return wildcard_match_icase(tmp, wanted_field->value.str);
		}
	case EVENT_FIELD_VALUE_TYPE_TIMEVAL: {
		/* Filtering for timeval fields is not implemented. */
		if (!node->warned_timeval_not_implemented) {
		     const char *name = event->sending_name;
		     i_warning("Event filter for timeval field '%s' is "
			       "currently not implemented. (event=%s, "
			       "source=%s:%u)",
			       wanted_field->key, name != NULL ? name : "",
			       source_filename, source_linenum);
			node->warned_timeval_not_implemented = TRUE;
		}
		return FALSE;
	}
	case EVENT_FIELD_VALUE_TYPE_IP:
		if (node->op != EVENT_FILTER_OP_CMP_EQ) {
			/* we only support IP equality comparisons */
			if (!node->warned_ip_inequality) {
				const char *name = event->sending_name;
				/* Use i_warning to prevent event filter recursions. */
				i_warning("Event filter for IP field '%s' "
					  "only supports equality operation "
					  "'=' not '%s'. (event=%s, source=%s:%u)",
					  wanted_field->key,
					  event_filter_export_query_expr_op(node->op),
					  name != NULL ? name : "",
					  source_filename, source_linenum);
				node->warned_ip_inequality = TRUE;
			}
			return FALSE;
		}
		if (wanted_field->value_type == EVENT_FIELD_VALUE_TYPE_IP) {
			return net_is_in_network(&field->value.ip,
						 &wanted_field->value.ip,
						 wanted_field->value.ip_bits);
		}
		if (use_strcmp) {
			/* If the matched value was a number, it was already
			   matched in the previous branch. So here we have a
			   non-wildcard IP, which can never be a match to an
			   IP. */
			if (!node->warned_type_mismatch) {
				const char *name = event->sending_name;
				/* Use i_warning to prevent event filter recursions. */
				i_warning("Event filter matches IP field "
					  "'%s' against non-IP value '%s'. "
					  "(event=%s, source=%s:%u)",
					  wanted_field->key,
					  wanted_field->value.str,
					  name != NULL ? name : "",
					  source_filename, source_linenum);
				node->warned_type_mismatch = TRUE;
			}
			return FALSE;
		}
		bool ret;
		T_BEGIN {
			ret = wildcard_match_icase(net_ip2addr(&field->value.ip),
						   wanted_field->value.str);
		} T_END;
		return ret;
	case EVENT_FIELD_VALUE_TYPE_STRLIST:
		/* check if the value is (or is not) on the list,
		   only string matching makes sense here. */
		if (node->op != EVENT_FILTER_OP_CMP_EQ) {
			if (!node->warned_string_inequality) {
				const char *name = event->sending_name;
				i_warning("Event filter for string list field "
					  "'%s' only supports equality "
					  "operation '=' not '%s'. (event=%s, "
					  "source=%s:%u)",
					  wanted_field->key,
					  event_filter_export_query_expr_op(node->op),
					  name != NULL ? name : "",
					  source_filename, source_linenum);
				node->warned_string_inequality = TRUE;
			}
			return FALSE;
		}
		return event_match_strlist(event, wanted_field, use_strcmp);
	}
	i_unreached();
}

static bool
event_filter_query_match_cmp(struct event_filter_node *node,
			     struct event *event, const char *source_filename,
			     unsigned int source_linenum,
			     enum event_filter_log_type log_type)
{
	i_assert((node->op == EVENT_FILTER_OP_CMP_EQ) ||
		 (node->op == EVENT_FILTER_OP_CMP_GT) ||
		 (node->op == EVENT_FILTER_OP_CMP_LT) ||
		 (node->op == EVENT_FILTER_OP_CMP_GE) ||
		 (node->op == EVENT_FILTER_OP_CMP_LE));

	switch (node->type) {
		case EVENT_FILTER_NODE_TYPE_LOGIC:
			i_unreached();
		case EVENT_FILTER_NODE_TYPE_EVENT_NAME_EXACT:
			return (event->sending_name != NULL) &&
			       strcmp(event->sending_name, node->str) == 0;
		case EVENT_FILTER_NODE_TYPE_EVENT_NAME_WILDCARD:
			return (event->sending_name != NULL) &&
			       wildcard_match(event->sending_name, node->str);
		case EVENT_FILTER_NODE_TYPE_EVENT_SOURCE_LOCATION:
			return !((source_linenum != node->intmax &&
				  node->intmax != 0) ||
				 source_filename == NULL ||
				 strcmp(event->source_filename, node->str) != 0);
		case EVENT_FILTER_NODE_TYPE_EVENT_CATEGORY:
			return event_has_category(event, node, log_type);
		case EVENT_FILTER_NODE_TYPE_EVENT_FIELD_EXACT:
			return event_match_field(event, node, TRUE, source_filename, source_linenum);
		case EVENT_FILTER_NODE_TYPE_EVENT_FIELD_WILDCARD:
		case EVENT_FILTER_NODE_TYPE_EVENT_FIELD_NUMERIC_WILDCARD:
			return event_match_field(event, node, FALSE, source_filename, source_linenum);
	}

	i_unreached();
}

bool
event_filter_query_match_eval(struct event_filter_node *node,
			      struct event *event, const char *source_filename,
			      unsigned int source_linenum,
			      enum event_filter_log_type log_type)
{
	switch (node->op) {
	case EVENT_FILTER_OP_CMP_EQ:
	case EVENT_FILTER_OP_CMP_GT:
	case EVENT_FILTER_OP_CMP_LT:
	case EVENT_FILTER_OP_CMP_GE:
	case EVENT_FILTER_OP_CMP_LE:
		return event_filter_query_match_cmp(node, event, source_filename,
						    source_linenum, log_type);
	case EVENT_FILTER_OP_AND:
		return event_filter_query_match_eval(node->children[0], event,
						     source_filename, source_linenum,
						     log_type) &&
		       event_filter_query_match_eval(node->children[1], event,
						     source_filename, source_linenum,
						     log_type);
	case EVENT_FILTER_OP_OR:
		return event_filter_query_match_eval(node->children[0], event,
						     source_filename, source_linenum,
						     log_type) ||
		       event_filter_query_match_eval(node->children[1], event,
						     source_filename, source_linenum,
						     log_type);
	case EVENT_FILTER_OP_NOT:
		return !event_filter_query_match_eval(node->children[0], event,
						      source_filename, source_linenum,
						      log_type);
	}

	i_unreached();
}

static bool
event_filter_query_match(const struct event_filter_query_internal *query,
			 struct event *event, const char *source_filename,
			 unsigned int source_linenum,
			 const struct failure_context *ctx)
{
	enum event_filter_log_type log_type;

	i_assert(ctx->type < N_ELEMENTS(event_filter_log_type_map));
	log_type = event_filter_log_type_map[ctx->type].log_type;

	return event_filter_query_match_eval(query->expr, event, source_filename,
					     source_linenum, log_type);
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
	if (filter == NULL)
		return FALSE;
	return event_filter_match_source(filter, event, event->source_filename,
					 event->source_linenum, ctx);
}

bool event_filter_match_source(struct event_filter *filter, struct event *event,
			       const char *source_filename,
			       unsigned int source_linenum,
			       const struct failure_context *ctx)
{
	const struct event_filter_query_internal *query;

	i_assert(!filter->fragment);

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

	i_assert(!filter->fragment);

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
event_filter_query_update_category(struct event_filter_query_internal *query,
				   struct event_filter_node *node,
				   struct event_category *category,
				   bool add)
{
	if (node == NULL)
		return;

	switch (node->type) {
	case EVENT_FILTER_NODE_TYPE_LOGIC:
		event_filter_query_update_category(query, node->children[0], category, add);
		event_filter_query_update_category(query, node->children[1], category, add);
		break;
	case EVENT_FILTER_NODE_TYPE_EVENT_NAME_EXACT:
	case EVENT_FILTER_NODE_TYPE_EVENT_NAME_WILDCARD:
	case EVENT_FILTER_NODE_TYPE_EVENT_SOURCE_LOCATION:
	case EVENT_FILTER_NODE_TYPE_EVENT_FIELD_EXACT:
	case EVENT_FILTER_NODE_TYPE_EVENT_FIELD_WILDCARD:
	case EVENT_FILTER_NODE_TYPE_EVENT_FIELD_NUMERIC_WILDCARD:
		break;
	case EVENT_FILTER_NODE_TYPE_EVENT_CATEGORY:
		if (node->category.name == NULL)
			break; /* log type */

		if (add) {
			if (node->category.ptr != NULL)
				break;

			if (strcmp(node->category.name, category->name) == 0)
				node->category.ptr = category;
		} else {
			if (node->category.ptr == category)
				node->category.ptr = NULL;
		}
		break;
	}
}

static void event_filter_category_registered(struct event_category *category)
{
	const bool add = category->internal != NULL;
	struct event_filter_query_internal *query;
	struct event_filter *filter;

	for (filter = event_filters; filter != NULL; filter = filter->next) {
		array_foreach_modifiable(&filter->queries, query) {
			event_filter_query_update_category(query, query->expr,
							   category, add);
		}
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
