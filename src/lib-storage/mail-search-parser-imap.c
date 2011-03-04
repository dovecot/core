/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "imap-arg.h"
#include "mail-search-parser-private.h"

struct imap_arg_stack {
	struct imap_arg_stack *prev;

	const struct imap_arg *args;
};

struct imap_mail_search_parser {
	struct mail_search_parser parser;

	struct imap_arg_stack root, *cur;
};

static int imap_search_parse_key(struct mail_search_parser *_parser,
				 const char **key_r)
{
	struct imap_mail_search_parser *parser =
		(struct imap_mail_search_parser *)_parser;
	const struct imap_arg *arg = parser->cur->args;
	struct imap_arg_stack *stack;

	switch (arg->type) {
	case IMAP_ARG_NIL:
		_parser->error = "Unexpected NIL";
		return -1;
	case IMAP_ARG_ATOM:
		*key_r = imap_arg_as_astring(arg);
		break;
	case IMAP_ARG_STRING:
	case IMAP_ARG_LITERAL:
		_parser->error = t_strconcat(
			"Unexpected string as search key: ",
			imap_arg_as_astring(arg), NULL);
		return -1;
	case IMAP_ARG_LIST:
		stack = p_new(_parser->pool, struct imap_arg_stack, 1);
		stack->prev = parser->cur;
		stack->args = imap_arg_as_list(arg);

		parser->cur->args++;
		parser->cur = stack;

		*key_r = MAIL_SEARCH_PARSER_KEY_LIST;
		return 1;
	case IMAP_ARG_EOL:
		parser->cur = parser->cur->prev;
		return 0;
	case IMAP_ARG_LITERAL_SIZE:
	case IMAP_ARG_LITERAL_SIZE_NONSYNC:
		i_unreached();
	}
	parser->cur->args++;
	return 1;
}

static int imap_search_parse_string(struct mail_search_parser *_parser,
				    const char **value_r)
{
	struct imap_mail_search_parser *parser =
		(struct imap_mail_search_parser *)_parser;
	const struct imap_arg *arg = parser->cur->args;

	switch (arg->type) {
	case IMAP_ARG_NIL:
		_parser->error = "Unexpected NIL";
		return -1;
	case IMAP_ARG_ATOM:
	case IMAP_ARG_STRING:
	case IMAP_ARG_LITERAL:
		*value_r = imap_arg_as_astring(arg);
		break;
	case IMAP_ARG_LIST:
		_parser->error = "Unexpected (";
		return -1;
	case IMAP_ARG_EOL:
		_parser->error = "Missing parameter for search key";
		return -1;
	case IMAP_ARG_LITERAL_SIZE:
	case IMAP_ARG_LITERAL_SIZE_NONSYNC:
		i_unreached();
	}
	parser->cur->args++;
	return 1;
}

static bool
imap_search_parse_skip_next(struct mail_search_parser *_parser, const char *str)
{
	struct imap_mail_search_parser *parser =
		(struct imap_mail_search_parser *)_parser;
	const char *arg;

	if (!imap_arg_get_astring(parser->cur->args, &arg))
		return FALSE;
	if (strcasecmp(arg, str) != 0)
		return FALSE;

	parser->cur->args++;
	return TRUE;
}

static const struct mail_search_parser_vfuncs mail_search_parser_imap_vfuncs = {
	imap_search_parse_key,
	imap_search_parse_string,
	imap_search_parse_skip_next
};

struct mail_search_parser *
mail_search_parser_init_imap(const struct imap_arg *args)
{
	struct imap_mail_search_parser *parser;
	pool_t pool;

	pool = pool_alloconly_create("imap search parser", 1024);
	parser = p_new(pool, struct imap_mail_search_parser, 1);
	parser->parser.pool = pool;
	parser->parser.v = mail_search_parser_imap_vfuncs;
	parser->root.args = args;
	parser->cur = &parser->root;
	return &parser->parser;
}
