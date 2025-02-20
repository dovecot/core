/* Copyright (c) 2024 Dovecot authors, see the included COPYING file */

%define api.pure full
%define api.prefix {var_expand_parser_}
%define parse.error verbose
%lex-param {void *scanner}
%parse-param {struct var_expand_parser_state *state}
%locations
%defines

%{

#include "lib.h"
#include "strnum.h"
#include "str.h"
#include "array.h"

#include "var-expand-private.h"
#include "var-expand-parser-private.h"
#include "var-expand-parser.h"
#include "expansion.h"

#pragma GCC diagnostic push

/* ignore strict bool warnings in generated code */
#ifdef HAVE_STRICT_BOOL
#  pragma GCC diagnostic ignored "-Wstrict-bool"
#endif
#pragma GCC diagnostic ignored "-Wpragmas"
#pragma GCC diagnostic ignored "-Wunknown-warning-option"
/* ignore sign comparison errors (buggy flex) */
#pragma GCC diagnostic ignored "-Wsign-compare"
/* ignore unused functions */
#pragma GCC diagnostic ignored "-Wunused-function"
/* ignore unused parameters */
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void yyerror(YYLTYPE *loc, struct var_expand_parser_state *state, const char *error);

extern int yylex(void *, void *, void *);
extern void var_expand_parser_lex_init_extra(void*, void*);

#define scanner state->scanner

/* List of likely non-variable names */
static const char *const filter_var_names[] = {
	"literal",
	"lookup",
	"if",
	"calculate",
	NULL
};

static void register_variable(VAR_EXPAND_PARSER_STYPE *state, const char *name,
			      bool maybe_func)
{
	/* When parsing the first item on the line, we end up here because
	   it could be function or variable. This list is the most common likely
	   function names that we exclude, and avoid them getting mistakenly added
	   into list of variables. We can't exclude every function, because there
	   are some functions that can also be variables, like domain. */
	if (maybe_func && str_array_find(filter_var_names, name))
		return;

	/* see if it is there yet */
	if (array_bsearch(&state->variables, &name, i_strcmp_p) != NULL)
		return;
	array_push_back(&state->variables, &name);
	array_sort(&state->variables, i_strcmp_p);
}

static void
link_argument(VAR_EXPAND_PARSER_STYPE *state, struct var_expand_parameter *par)
{
	/* First argument, just put it here */
	if (state->params == NULL) {
		state->params = par;
		return;
	}

	struct var_expand_parameter *ptr = state->params;
	struct var_expand_parameter *prev = NULL;

	if (par->idx > -1) {
		/* Parameters with index number go first, and are sorted by idx */
		while (ptr != NULL && ptr->idx > -1 && ptr->idx < par->idx) {
			prev = ptr;
			ptr = ptr->next;
		}
	} else {
		/* Named ones go after, and are sorted by key */
		while (ptr != NULL && (ptr->idx > -1 ||
				       strcmp(ptr->key, par->key) < 0)) {
			prev = ptr;
			ptr = ptr->next;
		}
	}

	/* We should now have a position where to place the key, */
	if (ptr != NULL && par->idx == -1 && strcmp(ptr->key, par->key) >= 0) {
		if (prev == NULL) {
			/* prepend it as first */
			par->next = state->params;
			state->params = par;
		} else {
			/* prepend it to previous item */
			par->next = prev->next;
			prev->next = par;
		}
	} else if (ptr == NULL) {
		/* append it at end of list */
		i_assert(prev != NULL);
		prev->next = par;
	} else if ((ptr->idx == -1 && par->idx > -1) ||
        	   (ptr->idx > -1 && par->idx < ptr->idx)) {
		if (prev == NULL) {
			/* prepend it as first */
			par->next = state->params;
			state->params = par;
		} else {
			/* prepend it to previous item */
			par->next = prev->next;
			prev->next = par;
		}
	} else {
		/* prepend it to current item */
		par->next = ptr->next;
		ptr->next = par;
	}
}

static void
push_named_argument(VAR_EXPAND_PARSER_STYPE *state, const char *name,
		    enum var_expand_parameter_value_type type,
		    const union var_expand_parameter_value *value)
{
	struct var_expand_parameter *par =
		p_new(state->plist->pool, struct var_expand_parameter, 1);
	par->idx = -1;
	/* Ensure keys are always lowercased */
	par->key = p_strdup(state->plist->pool, t_str_lcase(name));
	par->value_type = type;
	par->value = *value;
	if (type != VAR_EXPAND_PARAMETER_VALUE_TYPE_INT)
		par->value.str = p_strdup(state->plist->pool, value->str);
	if (type == VAR_EXPAND_PARAMETER_VALUE_TYPE_VARIABLE)
		register_variable(state, par->value.str, FALSE);
	link_argument(state, par);
}

static void
push_argument(VAR_EXPAND_PARSER_STYPE *state,
	      enum var_expand_parameter_value_type type,
	      const union var_expand_parameter_value *value)
{
	struct var_expand_parameter *par =
		p_new(state->plist->pool, struct var_expand_parameter, 1);
	par->idx = state->idx++;
	par->value_type = type;
	par->value = *value;
	if (type != VAR_EXPAND_PARAMETER_VALUE_TYPE_INT)
		par->value.str = p_strdup(state->plist->pool, value->str);
	if (type == VAR_EXPAND_PARAMETER_VALUE_TYPE_VARIABLE)
		register_variable(state, par->value.str, FALSE);
	link_argument(state, par);
}

static void make_new_program(VAR_EXPAND_PARSER_STYPE *pstate)
{
	struct var_expand_program *p =
		p_new(pstate->plist->pool, struct var_expand_program, 1);
	p->pool = pstate->plist->pool;
	pstate->pp->next = p;
	pstate->p = p;
}

static void push_function(VAR_EXPAND_PARSER_STYPE *state, const char *func)
{
	if (state->p == NULL)
		make_new_program(state);
	struct var_expand_statement *f =
		p_new(state->plist->pool, struct var_expand_statement, 1);
	f->function = func;
	if (state->p->first == NULL)
		register_variable(state, func, TRUE);
	f->params = state->params;
	if (state->p->first == NULL)
		state->p->first = f;
	else {
		struct var_expand_statement *ptr = state->p->first;
		while (ptr->next != NULL)
			ptr = ptr->next;
		ptr->next = f;
	}
	state->params = NULL;
	state->idx = 0;
}

static void push_new_program(VAR_EXPAND_PARSER_STYPE *pstate)
{
	pstate->pp = pstate->p;
	pstate->p = NULL;
}

static union var_expand_parameter_value tmp_value;

%}

%token PERC OCBRACE CCBRACE PIPE OBRACE CBRACE COMMA DOT QUOTE EQ PLUS MINUS STAR SLASH
%token <str> NAME
%token <str> VALUE
%token <str> NUMBER

%type <oper> operator
%type <number> number
%type <key> key
%type <funcname> funcname

%%

var : expression_list
    ;

expression_list:
	       | expression_list expression { push_new_program(state); }
	       ;

expression: VALUE { i_zero(&tmp_value); tmp_value.str = str_c($1); push_argument(state, VAR_EXPAND_PARAMETER_VALUE_TYPE_STRING, &tmp_value); push_function(state, "literal"); state->p->only_literal = TRUE;}
          | OCBRACE filter_list CCBRACE
	  | PERC { i_zero(&tmp_value); tmp_value.str = "%"; push_argument(state, VAR_EXPAND_PARAMETER_VALUE_TYPE_STRING, &tmp_value); push_function(state, "literal"); state->p->only_literal = TRUE; }
	  | error { return -1; }
	  ;

filter_list: filter_list PIPE filter
	   | filter
	   ;

filter: func math_list
	|
	;


math_list:
	 | math
	 ;

math: operator number { i_zero(&tmp_value); tmp_value.num = $1; push_argument(state, VAR_EXPAND_PARAMETER_VALUE_TYPE_INT, &tmp_value); i_zero(&tmp_value); tmp_value.num = $2; push_argument(state, VAR_EXPAND_PARAMETER_VALUE_TYPE_INT, &tmp_value); push_function(state, "calculate"); }
    | operator NAME { i_zero(&tmp_value); tmp_value.num = $1; push_argument(state, VAR_EXPAND_PARAMETER_VALUE_TYPE_INT, &tmp_value); i_zero(&tmp_value); tmp_value.str = str_c($2); push_argument(state, VAR_EXPAND_PARAMETER_VALUE_TYPE_VARIABLE, &tmp_value); push_function(state, "calculate"); }
    ;

number: MINUS NUMBER { str_insert($2, 0, "-"); if (str_to_intmax(str_c($2), &$$) < 0) { yyerror (&yylloc, state, YY_("Not a number")); YYERROR; }; }
      | NUMBER { if (str_to_intmax(str_c($1), &$$) < 0) { yyerror (&yylloc, state, YY_("Not a number")); YYERROR; }; }
      ;

operator: PLUS { $$ = VAR_EXPAND_STATEMENT_OPER_PLUS; }
	| MINUS { $$ = VAR_EXPAND_STATEMENT_OPER_MINUS; }
	| STAR { $$ = VAR_EXPAND_STATEMENT_OPER_STAR; }
	| SLASH { $$ = VAR_EXPAND_STATEMENT_OPER_SLASH; }
	| PERC { $$ = VAR_EXPAND_STATEMENT_OPER_MODULO; }
	;

func  : funcname arguments { push_function(state, $1); }
      ;

funcname : NAME { $$ = p_strdup(state->plist->pool, str_c($1)); }
	| error { return -1; }
	;

arguments:
	 | OBRACE argument_list CBRACE
	 ;

argument_list: argument_list COMMA argument
	     | argument
	     ;

argument : VALUE { i_zero(&tmp_value); tmp_value.str = str_c($1); push_argument(state, VAR_EXPAND_PARAMETER_VALUE_TYPE_STRING, &tmp_value); }
	 | NAME { i_zero(&tmp_value); tmp_value.str = str_c($1); push_argument(state, VAR_EXPAND_PARAMETER_VALUE_TYPE_VARIABLE, &tmp_value); }
	 | number { i_zero(&tmp_value); tmp_value.num = $1; push_argument(state, VAR_EXPAND_PARAMETER_VALUE_TYPE_INT, &tmp_value); }
	 | key EQ number { i_zero(&tmp_value); tmp_value.num = $3; push_named_argument(state, $1, VAR_EXPAND_PARAMETER_VALUE_TYPE_INT, &tmp_value); }
	 | key EQ NAME { i_zero(&tmp_value); tmp_value.str = str_c($3); push_named_argument(state, $1, VAR_EXPAND_PARAMETER_VALUE_TYPE_VARIABLE, &tmp_value); }
	 | key EQ VALUE { i_zero(&tmp_value); tmp_value.str = str_c($3); push_named_argument(state, $1, VAR_EXPAND_PARAMETER_VALUE_TYPE_STRING, &tmp_value); }
	 | error { return -1; }
	 ;

key : NAME { $$ = p_strdup(state->plist->pool, str_c($1)); }
    | error { return -1; }
    ;

%%
