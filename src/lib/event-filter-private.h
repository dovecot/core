#ifndef EVENT_FILTER_PRIVATE_H
#define EVENT_FILTER_PRIVATE_H

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

enum event_filter_node_type {
	/* internal nodes */
	EVENT_FILTER_NODE_TYPE_LOGIC = 1, /* children */

	/* leaf nodes */
	EVENT_FILTER_NODE_TYPE_EVENT_NAME, /* str */
	EVENT_FILTER_NODE_TYPE_EVENT_SOURCE_LOCATION, /* str + int */
	EVENT_FILTER_NODE_TYPE_EVENT_CATEGORY, /* cat */
	EVENT_FILTER_NODE_TYPE_EVENT_FIELD, /* field */
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
		 * We may be dealing with one of two situations:
		 *
		 * (1) the category is registered
		 * (2) the category is not registered
		 *
		 * Regardless of which of the two cases we're dealing with,
		 * we have a name for it.  Additionally, if a category is
		 * registered, the category pointer is non-NULL.
		 */
		const char *name;
		struct event_category *ptr;
	} category;
	struct event_field field;
};

#endif
