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

/* mimic renaming done by bison's api.prefix %define */
#define YYSTYPE         EVENT_FILTER_PARSER_STYPE

#define YY_INPUT(buf, result, max_size) \
        result = event_filter_parser_input_proc(buf, max_size, yyscanner)
static size_t event_filter_parser_input_proc(char *buf, size_t size, yyscan_t scanner);

#ifdef __clang__
#pragma clang diagnostic push
/* ignore "unknown warning" warning if we're using unpatched clang */
#pragma clang diagnostic ignored "-Wunknown-warning-option"
/* ignore strict bool warnings in generated code */
#pragma clang diagnostic ignored "-Wstrict-bool"
#endif
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
[A-Za-z0-9:.*_-]+		{ yylval->str = t_strdup(yytext); return TOKEN; }
[ \t\n\r]			{ /* ignore */ }
.				{
					char msg[160];

					i_snprintf(msg, sizeof(msg),
						   "syntax error, unexpected character '%c'",
						   yytext[0]);

					event_filter_parser_error(yyextra, msg);
				}
%%
#ifdef __clang__
#pragma clang diagnostic pop
#endif

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
