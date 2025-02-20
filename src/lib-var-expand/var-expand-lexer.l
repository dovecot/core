/* Copyright (c) 2024 Dovecot authors, see the included COPYING file */

%option nounput
%option noinput
%option noyywrap
%option noyyalloc noyyrealloc noyyfree
%option reentrant
%option bison-locations
%option bison-bridge
%option never-interactive
%option prefix="var_expand_parser_"
%option stack

%{

#include "lib.h"
#include "unichar.h"
#include "str.h"
#include "var-expand-private.h"
#include "var-expand-parser-private.h"
#include "var-expand-parser.h"

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

/* mimic renaming done by bison's api.prefix %define */
#define YYSTYPE         VAR_EXPAND_PARSER_STYPE
#define YYLTYPE         VAR_EXPAND_PARSER_LTYPE

static size_t input_proc(char *buf, size_t size, yyscan_t scanner);
#define YY_INPUT(buf, result, max_size) \
	result = input_proc(buf, max_size, yyscanner);


#define INIT_STR STMT_START { \
	YYSTYPE *state = yyget_extra(yyscanner); \
	yylval->str = str_new(state->pool, 32); \
	} STMT_END

#ifndef VAR_EXPAND_PARSER_error
#  define VAR_EXPAND_PARSER_error 256
#endif

static int scanner_error(void *yyscanner, const char *msg);
static bool append_valid_utf8(void *yyscanner, YYSTYPE *state, const char *value);
#define append_valid_utf8(state, value) \
	if (!append_valid_utf8(yyscanner, (state), (value))) { \
		return VAR_EXPAND_PARSER_error; \
	}
%}

%x stringsq
%x stringdq
%x quote
%x expr

%%

<quote>{
  [\\]	       { yy_pop_state(yyscanner); str_append_c(yylval->str, '\\'); }
  x[0-9a-fA-F]{2}    {
    unsigned int c;
    if (str_to_uint_hex(yytext+1, &c) < 0 || c > 255) {
      return scanner_error(yyscanner, "Invalid character escape");
    }
    yy_pop_state(yyscanner); str_append_c(yylval->str, c);
  }
  [0-9]{1,3}   {
    unsigned int c;
    if (str_to_uint_oct(yytext, &c) < 0 || c > 255) {
      return scanner_error(yyscanner, "Invalid character escape");
    }
    yy_pop_state(yyscanner); str_append_c(yylval->str, c);
  }
  t	   { yy_pop_state(yyscanner); str_append_c(yylval->str, '\t'); }
  r	   { yy_pop_state(yyscanner); str_append_c(yylval->str, '\r'); }
  n	   { yy_pop_state(yyscanner); str_append_c(yylval->str, '\n'); }
  ["]	   { yy_pop_state(yyscanner); str_append_c(yylval->str, '"'); }
  [']      { yy_pop_state(yyscanner); str_append_c(yylval->str, '\''); }
  . { return scanner_error(yyscanner, "Invalid character escape"); }
}

<stringdq>{
  [\\]    { yy_push_state(quote, yyscanner); }
  ["]     { yy_pop_state(yyscanner); return VALUE; }
  [^"\\]* { append_valid_utf8(yylval, yytext); }
}

<stringsq>{
  [\\]    { yy_push_state(quote, yyscanner); }
  [']     { yy_pop_state(yyscanner); return VALUE; }
  [^'\\]* { append_valid_utf8(yylval, yytext); }
}

<expr>{
  "}"	    { yy_pop_state(yyscanner); return CCBRACE; }
  [ \t]     { /* ignore */ }
  \%        { return PERC; }
  [a-zA-Z\x80-\xff][a-zA-Z0-9_/;:.\x80-\xff-]* { INIT_STR; append_valid_utf8(yylval, yytext); return NAME; }
  \|        { return PIPE; }
  \(        { return OBRACE; }
  \)        { return CBRACE; }
  \,        { return COMMA; }
  = 	    { return EQ; }
  \+        { return PLUS; }
  -         { return MINUS; }
  \*        { return STAR; }
  \/        { return SLASH; }
  [']       { yy_push_state(stringsq, yyscanner); INIT_STR; }
  ["]       { yy_push_state(stringdq, yyscanner); INIT_STR; }
  [0-9]+    { INIT_STR; str_append(yylval->str, yytext); return NUMBER; }
}
y
"%{"	  { yy_push_state(expr, yyscanner); return OCBRACE; }
"%%{"     { INIT_STR; str_append(yylval->str, "%{"); return VALUE; }
"%"	  { return PERC; }
[^%]+     { INIT_STR; str_append(yylval->str, yytext); return VALUE; }

%%

extern void var_expand_parser_error(YYLTYPE *loc, YYSTYPE *state, const char *error);
void var_expand_parser_error(YYLTYPE *loc ATTR_UNUSED, YYSTYPE *state, const char *error)
{
	state->failed = TRUE;
	state->error = p_strdup(state->pool, error);
}

static int scanner_error(void *scanner, const char *msg)
{
	YYSTYPE *state = yyget_extra(scanner);
	struct yyguts_t *yyg = (struct yyguts_t *)scanner;
	var_expand_parser_error(yylloc, state, msg);
	return VAR_EXPAND_PARSER_error;
}

void *yyalloc(size_t bytes, void* yyscanner)
{
	YYSTYPE *state = yyget_extra(yyscanner);
	return  p_malloc(state->pool, bytes);
}

void *yyrealloc (void *ptr, size_t bytes, void *yyscanner)
{
	YYSTYPE *state = yyget_extra(yyscanner);
	return p_realloc(state->pool, ptr, SIZE_MAX, bytes);
}

void yyfree(void *ptr, void *yyscanner)
{
	YYSTYPE *state = yyget_extra(yyscanner);
	p_free(state->pool, ptr);
}

#undef append_valid_utf8
static bool append_valid_utf8(void *scanner, YYSTYPE *state, const char *value)
{
	if (!uni_utf8_str_is_valid(value)) {
		(void)scanner_error(scanner, "Invalid UTF-8 string");
		return FALSE;
	}
	str_append(state->str, value);
	return TRUE;
}

#define INPUT_POS(state) (state->input + state->input_pos)

static size_t input_proc(char *buf, size_t size, yyscan_t scanner)
{
	YYSTYPE *state = yyget_extra(scanner);
	size_t ret = 0;
	if (size > state->left) {
		memcpy(buf, INPUT_POS(state), state->left);
		state->input_pos += state->left;
		ret = state->left;
		state->left = 0;
	} else {
		memcpy(buf, INPUT_POS(state), size);
		state->left -= size;
		state->input_pos += size;
		ret = size;
	}
	return ret;
}
