/* Copyright (c) 2020 Dovecot authors, see the included COPYING file */

%option nounput
%option noinput
%option noyywrap
%option noyyalloc noyyrealloc noyyfree
%option reentrant
%option bison-bridge
%option never-interactive
%option prefix="event_filter_parser_"

%{
#include "lib.h"
#include "str.h"
#include "event-filter-private.h"
#include "event-filter-parser.h"

#define YY_FATAL_ERROR(msg) { i_fatal("event filter parsing: %s", (msg)); }

/* mimic renaming done by bison's api.prefix %define */
#define YYSTYPE         EVENT_FILTER_PARSER_STYPE

#define YY_INPUT(buf, result, max_size) \
        result = event_filter_parser_input_proc(buf, max_size, yyscanner)
static size_t event_filter_parser_input_proc(char *buf, size_t size, yyscan_t scanner);

#pragma GCC diagnostic push

/* ignore strict bool warnings in generated code */
#ifdef HAVE_STRICT_BOOL
#  pragma GCC diagnostic ignored "-Wstrict-bool"
#endif
/* ignore sign comparison errors (buggy flex) */
#pragma GCC diagnostic ignored "-Wsign-compare"
/* ignore unused functions */
#pragma GCC diagnostic ignored "-Wunused-function"
/* ignore unused parameters */
#pragma GCC diagnostic ignored "-Wunused-parameter"

%}

%x string

%%
	string_t *str_buf = NULL;

\"				{
					BEGIN(string);

					str_buf = t_str_new(128);
				}
<string>\"			{
					yylval->str = str_c(str_buf);
					BEGIN(INITIAL);
					return STRING;
				}
	/* Note: these have to match the event_filter_append_escaped() behavior */
<string>[^\\"]+			{ str_append(str_buf, yytext); }
<string>\\\\			{ str_append_c(str_buf, '\\'); }
<string>\\\"			{ str_append_c(str_buf, '"'); }
<string>\\.			{ str_append(str_buf, yytext); }

[Aa][Nn][Dd]			{ return AND; }
[Oo][Rr]			{ return OR; }
[Nn][Oo][Tt]			{ return NOT; }
[<>=()]				{ return *yytext; }
[A-Za-z0-9:.*?/%_-]+		{ yylval->str = t_strdup(yytext); return TOKEN; }
[ \t\n\r]			{ /* ignore */ }
.				{
					/*
					 * We simply return the char to the
					 * and let the grammar error out
					 * with a syntax error.
					 *
					 * Note: The cast is significant
					 * since utf-8 bytes >=128 will
					 * otherwise result in sign
					 * extension and a negative int
					 * getting returned on some
					 * platforms (e.g., x86) which in
					 * turn confuses the parser.  E.g.,
					 * if:
					 *    *yytext = '\x80'
					 * we get:
					 *    *yytext             -> -128
					 *    (int) *yytext       -> -128
					 * which is wrong.  With the
					 * unsigned char cast, we get:
					 *    (u.c.) *yytext      -> 128
					 *    (int)(u.c.) *yytext -> 128
					 * which is correct.
					 */
					return (unsigned char) *yytext;
				}
%%

#pragma GCC diagnostic pop

void *yyalloc(size_t bytes, void* yyscanner ATTR_UNUSED)
{
	void *ptr = calloc(1, bytes);
	if (ptr == NULL)
		i_fatal_status(FATAL_OUTOFMEM, "calloc(1, %zu): Out of memory",
			       bytes);
	return ptr;
}

void *yyrealloc (void *ptr, size_t bytes, void *yyscanner ATTR_UNUSED)
{
	void *nptr = realloc(ptr, bytes);
	if (nptr == NULL)
		i_fatal_status(FATAL_OUTOFMEM, "realloc(ptr, %zu): Out of memory",
			       bytes);
	return nptr;
}

void yyfree(void *ptr, void *yyscanner ATTR_UNUSED)
{
	if (ptr == NULL)
		return;
	free(ptr);
}

static size_t event_filter_parser_input_proc(char *buf, size_t size, yyscan_t scanner)
{
	struct event_filter_parser_state *state;
	size_t num_bytes;

	state = event_filter_parser_get_extra(scanner);

	if (state->len == state->pos)
		return 0;

	i_assert(state->len > state->pos);

	num_bytes = I_MIN(state->len - state->pos, size);
	memcpy(buf, state->input + state->pos, num_bytes);
	state->pos += num_bytes;

	return num_bytes;
}
