#ifndef EVENT_FILTER_PRIVATE_H
#define EVENT_FILTER_PRIVATE_H

#include "event-filter.h"

enum event_filter_node_op {
	/* leaf nodes */
	EVENT_FILTER_OP_CMP_EQ = 1,
	EVENT_FILTER_OP_CMP_GT,
	EVENT_FILTER_OP_CMP_LT,
	EVENT_FILTER_OP_CMP_GE,
	EVENT_FILTER_OP_CMP_LE,

	/* internal nodes */
	EVENT_FILTER_OP_AND,
	EVENT_FILTER_OP_OR,
	EVENT_FILTER_OP_NOT,
};

struct event_filter {
	struct event_filter *prev, *next;

	pool_t pool;
	int refcount;
	ARRAY(struct event_filter_query_internal) queries;

	bool fragment;
	bool named_queries_only;
};

enum event_filter_node_type {
	/* internal nodes */
	EVENT_FILTER_NODE_TYPE_LOGIC = 1, /* children */

	/* leaf nodes */
	EVENT_FILTER_NODE_TYPE_EVENT_NAME_EXACT, /* str */
	EVENT_FILTER_NODE_TYPE_EVENT_NAME_WILDCARD, /* str */
	EVENT_FILTER_NODE_TYPE_EVENT_SOURCE_LOCATION, /* str + int */
	EVENT_FILTER_NODE_TYPE_EVENT_CATEGORY, /* cat */
	EVENT_FILTER_NODE_TYPE_EVENT_FIELD_EXACT, /* field */
	EVENT_FILTER_NODE_TYPE_EVENT_FIELD_WILDCARD, /* field */
	EVENT_FILTER_NODE_TYPE_EVENT_FIELD_NUMERIC_WILDCARD, /* field */
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

struct event_filter_node {
	enum event_filter_node_type type;
	enum event_filter_node_op op;

	/* internal node */
	struct event_filter_node *children[2];

	/* leaf node */
	const char *str;
	uintmax_t intmax;
	struct {
		/*
		 * We may be dealing with one of three situations:
		 *
		 * 1) the category is a special "log type" category
		 * 2) the category is a "normal" category which is:
		 *    a) registered
		 *    b) not registered
		 *
		 * A "log type" category is always stored here as the
		 * log_type enum value with the name and ptr members being
		 * NULL.
		 *
		 * A regular category always has a name.  Additionally, if
		 * it is registered, the category pointer is non-NULL.
		 */
		enum event_filter_log_type log_type;
		const char *name;
		struct event_category *ptr;
	} category;
	struct event_field field;

	bool ambiguous_unit:1;
	bool warned_ambiguous_unit:1;
	bool warned_string_inequality:1;
	bool warned_ip_inequality:1;
	bool warned_type_mismatch:1;
	bool warned_timeval_not_implemented:1;
};

bool event_filter_category_to_log_type(const char *name,
				       enum event_filter_log_type *log_type_r);

/* lexer & parser state */
struct event_filter_parser_state {
	void *scanner;
	const char *input;
	size_t len;
	size_t pos;

	pool_t pool;
	struct event_filter_node *output;
	const char *error;
	bool has_event_name:1;
};

int event_filter_parser_lex_init(void **scanner);
int event_filter_parser_lex_destroy(void *yyscanner);
int event_filter_parser_parse(struct event_filter_parser_state *state);
void event_filter_parser_set_extra(void *user, void *yyscanner);
void event_filter_parser_error(void *scan, const char *e);

/* the following are exposed to allow for unit testing */
bool
event_filter_query_match_eval(struct event_filter_node *node,
			      struct event *event, const char *source_filename,
			      unsigned int source_linenum,
			      enum event_filter_log_type log_type);
const char *
event_filter_category_from_log_type(enum event_filter_log_type log_type);
struct event_filter_node *
event_filter_get_expr_for_testing(struct event_filter *filter, unsigned int *count_r);

#endif
