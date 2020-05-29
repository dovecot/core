/* Copyright (c) 2020 Dovecot authors, see the included COPYING file */

%define api.pure
%define api.prefix {event_filter_parser_}
%lex-param {void *scanner}
%parse-param {struct event_filter_parser_state *state}

%defines

%{
#include "lib.h"
#include "lib-event-private.h"
#include "event-filter-private.h"

#define scanner state->scanner

#define YYERROR_VERBOSE

extern int event_filter_parser_lex(void *, void *);

void event_filter_parser_error(void *scan, const char *e)
{
	struct event_filter_parser_state *state = scan;

	state->error = t_strdup_printf("event filter: %s", e);
}

static struct event_filter_node *key_value(struct event_filter_parser_state *state,
					   const char *a, const char *b,
					   enum event_filter_node_op op)
{
	struct event_filter_node *node;
	enum event_filter_node_type type;

	if (strcmp(a, "event") == 0)
		type = EVENT_FILTER_NODE_TYPE_EVENT_NAME;
	else if (strcmp(a, "category") == 0)
		type = EVENT_FILTER_NODE_TYPE_EVENT_CATEGORY;
	else if (strcmp(a, "source_location") == 0)
		type = EVENT_FILTER_NODE_TYPE_EVENT_SOURCE_LOCATION;
	else
		type = EVENT_FILTER_NODE_TYPE_EVENT_FIELD;

	node = p_new(state->pool, struct event_filter_node, 1);
	node->type = type;
	node->op = op;

	switch (type) {
	case EVENT_FILTER_NODE_TYPE_LOGIC:
		i_unreached();
	case EVENT_FILTER_NODE_TYPE_EVENT_NAME:
		node->str = p_strdup(state->pool, b);
		state->has_event_name = TRUE;
		break;
	case EVENT_FILTER_NODE_TYPE_EVENT_SOURCE_LOCATION: {
		const char *colon = strrchr(b, ':');
		const char *file;
		uintmax_t line;

		/* split "filename:line-number", but also handle "filename" */
		if (colon != NULL) {
			if (str_to_uintmax(colon + 1, &line) < 0) {
				file = p_strdup(state->pool, b);
				line = 0;
			} else {
				file = p_strdup_until(state->pool, b, colon);
			}
		} else {
			file = p_strdup_empty(state->pool, b);
			line = 0;
		}

		node->str = file;
		node->intmax = line;
		break;
	}
	case EVENT_FILTER_NODE_TYPE_EVENT_CATEGORY:
		if (!event_filter_category_to_log_type(b, &node->category.log_type)) {
			node->category.name = p_strdup(state->pool, b);
			node->category.ptr = event_category_find_registered(b);
		}
		break;
	case EVENT_FILTER_NODE_TYPE_EVENT_FIELD:
		node->field.key = p_strdup(state->pool, a);
		node->field.value.str = p_strdup(state->pool, b);

		/* Filter currently supports only comparing strings
		   and numbers. */
		if (str_to_intmax(b, &node->field.value.intmax) < 0) {
			/* not a number - no problem
			   Either we have a string, or a number with wildcards */
			node->field.value.intmax = INT_MIN;
		}
		break;
	}

	return node;
}

static struct event_filter_node *logic(struct event_filter_parser_state *state,
				       struct event_filter_node *a,
				       struct event_filter_node *b,
				       enum event_filter_node_op op)
{
	struct event_filter_node *node;

	node = p_new(state->pool, struct event_filter_node, 1);
	node->type = EVENT_FILTER_NODE_TYPE_LOGIC;
	node->op = op;
	node->children[0] = a;
	node->children[1] = b;

	return node;
}

#ifdef __clang__
/* ignore "unknown warning" warning if we're using unpatched clang */
#pragma clang diagnostic ignored "-Wunknown-warning-option"
/* ignore strict bool warnings in generated code */
#pragma clang diagnostic ignored "-Wstrict-bool"
#endif
%}

%union {
	const char *str;
	enum event_filter_node_op op;
	struct event_filter_node *node;
};

%token <str> TOKEN STRING
%token AND OR NOT

%type <str> key value
%type <op> op
%type <node> expr key_value

%precedence NOT
%left AND OR

%%
filter : expr			{ state->output = $1; }
       | %empty			{ state->output = NULL; }
       ;

expr : expr AND expr		{ $$ = logic(state, $1, $3, EVENT_FILTER_OP_AND); }
     | expr OR expr		{ $$ = logic(state, $1, $3, EVENT_FILTER_OP_OR); }
     | NOT expr			{ $$ = logic(state, $2, NULL, EVENT_FILTER_OP_NOT); }
     | '(' expr ')'		{ $$ = $2; }
     | key_value		{ $$ = $1; }
     ;

key_value : key op value	{ $$ = key_value(state, $1, $3, $2); }
	  ;

key : TOKEN			{ $$ = $1; }
    | STRING			{ $$ = $1; }
    ;

value : TOKEN			{ $$ = $1; }
      | STRING			{ $$ = $1; }
      | AND			{ $$ = "and"; }
      | OR			{ $$ = "or"; }
      | NOT			{ $$ = "not"; }
      ;

op : '='			{ $$ = EVENT_FILTER_OP_CMP_EQ; }
   | '>'			{ $$ = EVENT_FILTER_OP_CMP_GT; }
   | '<'			{ $$ = EVENT_FILTER_OP_CMP_LT; }
   | '>' '='			{ $$ = EVENT_FILTER_OP_CMP_GE; }
   | '<' '='			{ $$ = EVENT_FILTER_OP_CMP_LE; }
   ;
%%
