/* Copyright (c) 2016-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "str.h"
#include "imap-date.h"
#include "imap-seqset.h"
#include "imap-utf7.h"
#include "imap-util.h"
#include "mail-search-parser.h"
#include "mail-search-mime-register.h"
#include "mail-search-mime-build.h"
#include "mail-search-mime.h"

struct mail_search_mime_register {
	ARRAY(struct mail_search_mime_register_arg) args;

	bool args_sorted:1;
};

struct mail_search_mime_register *mail_search_mime_register = NULL;

static void
mail_search_register_add_default(void);

/*
 * Register
 */

static struct mail_search_mime_register *
mail_search_mime_register_init(void)
{
	struct mail_search_mime_register *reg =
		mail_search_mime_register;
	if (reg == NULL) {
		reg = i_new(struct mail_search_mime_register, 1);
		i_array_init(&reg->args, 64);

		mail_search_mime_register = reg;
		mail_search_register_add_default();
	}

	return reg;
}

void mail_search_mime_register_deinit(void)
{
	struct mail_search_mime_register *reg =
		mail_search_mime_register;

	mail_search_mime_register = NULL;
	if (reg == NULL)
		return;

	array_free(&reg->args);
	i_free(reg);
}

void mail_search_mime_register_add(
			      const struct mail_search_mime_register_arg *arg,
			      unsigned int count)
{
	struct mail_search_mime_register *reg =
		mail_search_mime_register_init();

	array_append(&reg->args, arg, count);
	reg->args_sorted = FALSE;
}

static int
mail_search_mime_register_arg_cmp(
	const struct mail_search_mime_register_arg *arg1,
	const struct mail_search_mime_register_arg *arg2)
{
	return strcmp(arg1->key, arg2->key);
}

const struct mail_search_mime_register_arg *
mail_search_mime_register_get(unsigned int *count_r)
{
	struct mail_search_mime_register *reg =
		mail_search_mime_register_init();

	if (!reg->args_sorted) {
		array_sort(&reg->args, mail_search_mime_register_arg_cmp);
		reg->args_sorted = TRUE;
	}

	return array_get(&reg->args, count_r);
}

const struct mail_search_mime_register_arg *
mail_search_mime_register_find(const char *key)
{
	struct mail_search_mime_register_arg arg;
	struct mail_search_mime_register *reg =
		mail_search_mime_register_init();

	if (!reg->args_sorted) {
		array_sort(&reg->args, mail_search_mime_register_arg_cmp);
		reg->args_sorted = TRUE;
	}

	arg.key = key;
	return array_bsearch(&reg->args, &arg, mail_search_mime_register_arg_cmp);
}

/*
 * Default MIMEPART args
 */

static struct mail_search_mime_arg *
mail_search_mime_not(struct mail_search_mime_build_context *ctx)
{
	struct mail_search_mime_arg *smarg;

	if (mail_search_mime_build_key(ctx, ctx->parent, &smarg) < 0)
		return NULL;

	smarg->match_not = !smarg->match_not;
	return smarg;
}

static struct mail_search_mime_arg *
mail_search_mime_or(struct mail_search_mime_build_context *ctx)
{
	struct mail_search_mime_arg *smarg, **subargs;

	/* <search-key1> <search-key2> */
	smarg = mail_search_mime_build_new(ctx, SEARCH_MIME_OR);

	subargs = &smarg->value.subargs;
	do {
		if (mail_search_mime_build_key(ctx, smarg, subargs) < 0)
			return NULL;
		subargs = &(*subargs)->next;

		/* <key> OR <key> OR ... <key> - put them all
		   under one SEARCH_MIME_OR list. */
	} while (mail_search_parse_skip_next(ctx->ctx->parser, "OR"));

	if (mail_search_mime_build_key(ctx, smarg, subargs) < 0)
		return NULL;
	return smarg;
}

#define CALLBACK_STR(_func, _type) \
static struct mail_search_mime_arg *\
mail_search_mime_##_func(struct mail_search_mime_build_context *ctx) \
{ \
	return mail_search_mime_build_str(ctx, _type); \
}

static struct mail_search_mime_arg *
arg_new_date(struct mail_search_mime_build_context *ctx,
	     enum mail_search_mime_arg_type type)
{
	struct mail_search_mime_arg *smarg;
	const char *value;

	smarg = mail_search_mime_build_new(ctx, type);
	if (mail_search_parse_string(ctx->ctx->parser, &value) < 0)
		return NULL;
	if (!imap_parse_date(value, &smarg->value.time)) {
		ctx->ctx->_error = "Invalid search date parameter";
		return NULL;
	}
	return smarg;
}

#define CALLBACK_DATE(_func, _type) \
static struct mail_search_mime_arg *\
mail_search_mime_##_func(struct mail_search_mime_build_context *ctx) \
{ \
	return arg_new_date(ctx, _type); \
}
CALLBACK_DATE(sentbefore, SEARCH_MIME_SENTBEFORE)
CALLBACK_DATE(senton, SEARCH_MIME_SENTON)
CALLBACK_DATE(sentsince, SEARCH_MIME_SENTSINCE)

static struct mail_search_mime_arg *
mail_search_mime_size(struct mail_search_mime_build_context *ctx)
{
	struct mail_search_mime_arg *smarg;
	enum mail_search_mime_arg_type type;
	const char *key, *value;
	uoff_t size;

	if (mail_search_parse_key(ctx->ctx->parser, &key) <= 0) {
		ctx->ctx->_error = "Invalid MIMEPART SIZE key type";
		return NULL;
	}

	key = t_str_ucase(key);
	if (strcmp(key, "LARGER") == 0)
		type = SEARCH_MIME_SIZE_LARGER;
	else 	if (strcmp(key, "SMALLER") == 0)
		type = SEARCH_MIME_SIZE_SMALLER;
	else {
		type = SEARCH_MIME_SIZE_EQUAL;
		value = key;
	}

	if (type != SEARCH_MIME_SIZE_EQUAL &&
		mail_search_parse_string(ctx->ctx->parser, &value) < 0) {
		ctx->ctx->_error = "Invalid MIMEPART SIZE value";
		return NULL;
	}

	if (str_to_uoff(value, &size) < 0) {
		ctx->ctx->_error = "Invalid MIMEPART SIZE value";
		return NULL;
	}

	smarg = mail_search_mime_build_new(ctx, type);
	smarg->value.size = size;
	return smarg;
}

CALLBACK_STR(description, SEARCH_MIME_DESCRIPTION)
CALLBACK_STR(encoding, SEARCH_MIME_ENCODING)
CALLBACK_STR(id, SEARCH_MIME_ID)
CALLBACK_STR(language, SEARCH_MIME_LANGUAGE)
CALLBACK_STR(location, SEARCH_MIME_LOCATION)
CALLBACK_STR(md5, SEARCH_MIME_MD5)

CALLBACK_STR(type, SEARCH_MIME_TYPE)
CALLBACK_STR(subtype, SEARCH_MIME_SUBTYPE)

CALLBACK_STR(bcc, SEARCH_MIME_BCC)
CALLBACK_STR(cc, SEARCH_MIME_CC)
CALLBACK_STR(from, SEARCH_MIME_FROM)
CALLBACK_STR(in_reply_to, SEARCH_MIME_IN_REPLY_TO)
CALLBACK_STR(message_id, SEARCH_MIME_MESSAGE_ID)
CALLBACK_STR(reply_to, SEARCH_MIME_REPLY_TO)
CALLBACK_STR(sender, SEARCH_MIME_SENDER)
CALLBACK_STR(subject, SEARCH_MIME_SUBJECT)
CALLBACK_STR(to, SEARCH_MIME_TO)

static struct mail_search_mime_arg *
arg_new_field(struct mail_search_mime_build_context *ctx,
	enum mail_search_mime_arg_type type)
{
	struct mail_search_mime_arg *smarg;
	const char *field_name, *value;

	/* <field-name> <string> */
	if (mail_search_parse_string(ctx->ctx->parser, &field_name) < 0)
		return NULL;
	if (mail_search_build_get_utf8(ctx->ctx, field_name, &field_name) < 0)
		return NULL;
	if (mail_search_parse_string(ctx->ctx->parser, &value) < 0)
		return NULL;
	if (mail_search_build_get_utf8(ctx->ctx, value, &value) < 0)
		return NULL;

	smarg = mail_search_mime_build_new(ctx, type);
	smarg->field_name = str_ucase(p_strdup(ctx->ctx->pool, field_name));
	smarg->value.str = value;

	return smarg;
}

static struct mail_search_mime_arg *
mail_search_mime_param(struct mail_search_mime_build_context *ctx)
{
	return arg_new_field
		(ctx, SEARCH_MIME_PARAM);
}

static struct mail_search_mime_arg *
mail_search_mime_header(struct mail_search_mime_build_context *ctx)
{
	return arg_new_field
		(ctx, SEARCH_MIME_HEADER);
}

static struct mail_search_mime_arg *
arg_new_body(struct mail_search_mime_build_context *ctx,
	     enum mail_search_mime_arg_type type)
{
	struct mail_search_mime_arg *smarg;

	smarg = mail_search_mime_build_str(ctx, type);
	if (smarg == NULL)
		return NULL;

	if (mail_search_build_get_utf8(ctx->ctx, smarg->value.str,
				       &smarg->value.str) < 0)
		return NULL;
	return smarg;
}

#define CALLBACK_BODY(_func, _type) \
static struct mail_search_mime_arg *\
mail_search_mime_##_func(struct mail_search_mime_build_context *ctx) \
{ \
	return arg_new_body(ctx, _type); \
}
CALLBACK_BODY(body, SEARCH_MIME_BODY)
CALLBACK_BODY(text, SEARCH_MIME_TEXT)

static struct mail_search_mime_arg *
mail_search_mime_disposition(struct mail_search_mime_build_context *ctx)
{
	struct mail_search_mime_arg *smarg;
	const char *key, *value;

	if (mail_search_parse_key(ctx->ctx->parser, &key) <= 0) {
		ctx->ctx->_error = "Invalid MIMEPART DISPOSITION key type";
		return NULL;
	}

	key = t_str_ucase(key);
	if (strcmp(key, "TYPE") == 0) {
		if (mail_search_parse_string(ctx->ctx->parser, &value) < 0) {
			ctx->ctx->_error = "Invalid MIMEPART DISPOSITION TYPE value";
			return NULL;
		}
		smarg = mail_search_mime_build_new
			(ctx, SEARCH_MIME_DISPOSITION_TYPE);
		smarg->value.str = p_strdup(ctx->ctx->pool, value);
		return smarg;
	} else 	if (strcmp(key, "PARAM") == 0) {
		return arg_new_field
			(ctx, SEARCH_MIME_DISPOSITION_PARAM);
	}

	ctx->ctx->_error = "Invalid MIMEPART DISPOSITION key type";
	return NULL;
}

static struct mail_search_mime_arg *
mail_search_mime_depth(struct mail_search_mime_build_context *ctx)
{
	struct mail_search_mime_arg *smarg;
	enum mail_search_mime_arg_type type;
	const char *key, *value;
	unsigned int depth;

	if (mail_search_parse_key(ctx->ctx->parser, &key) <= 0) {
		ctx->ctx->_error = "Invalid MIMEPART DEPTH key";
		return NULL;
	}

	key = t_str_ucase(key);
	if (strcmp(key, "MIN") == 0)
		type = SEARCH_MIME_DEPTH_MIN;
	else 	if (strcmp(key, "MAX") == 0)
		type = SEARCH_MIME_DEPTH_MAX;
	else {
		type = SEARCH_MIME_DEPTH_EQUAL;
		value = key;
	}

	if (type != SEARCH_MIME_DEPTH_EQUAL &&
		mail_search_parse_string(ctx->ctx->parser, &value) < 0) {
		ctx->ctx->_error = "Invalid MIMEPART DEPTH value";
		return NULL;
	}

	if (str_to_uint(value, &depth) < 0) {
		ctx->ctx->_error = "Invalid MIMEPART DEPTH level";
		return NULL;
	}

	smarg = mail_search_mime_build_new(ctx, type);
	smarg->value.number = depth;
	return smarg;
}

static struct mail_search_mime_arg *
mail_search_mime_index(struct mail_search_mime_build_context *ctx)
{
	struct mail_search_mime_arg *smarg;
	const char *value;
	unsigned int index;

	if (mail_search_parse_string(ctx->ctx->parser, &value) < 0) {
		ctx->ctx->_error = "Invalid MIMEPART INDEX value";
		return NULL;
	}

	if (str_to_uint(value, &index) < 0) {
		ctx->ctx->_error = "Invalid MIMEPART INDEX number";
		return NULL;
	}

	smarg = mail_search_mime_build_new
		(ctx, SEARCH_MIME_INDEX);
	smarg->value.number = index;
	return smarg;
}

static struct mail_search_mime_arg *
mail_search_mime_filename(struct mail_search_mime_build_context *ctx)
{
	struct mail_search_mime_arg *smarg;
	enum mail_search_mime_arg_type type;
	const char *key, *value;

	if (mail_search_parse_key(ctx->ctx->parser, &key) <= 0) {
		ctx->ctx->_error = "Invalid MIMEPART FILENAME match type";
		return NULL;
	}

	key = t_str_ucase(key);
	if (strcmp(key, "IS") == 0)
		type = SEARCH_MIME_FILENAME_IS;
	else 	if (strcmp(key, "CONTAINS") == 0)
		type = SEARCH_MIME_FILENAME_CONTAINS;
	else 	if (strcmp(key, "BEGINS") == 0)
		type = SEARCH_MIME_FILENAME_BEGINS;
	else 	if (strcmp(key, "ENDS") == 0)
		type = SEARCH_MIME_FILENAME_ENDS;
	else {
		ctx->ctx->_error = "Invalid MIMEPART FILENAME match type";
		return NULL;
	}

	if (mail_search_parse_string(ctx->ctx->parser, &value) < 0) {
		ctx->ctx->_error = "Invalid MIMEPART FILENAME string value";
		return NULL;
	}

	if (mail_search_build_get_utf8(ctx->ctx, value, &value) < 0) {
		ctx->ctx->_error = "Invalid MIMEPART FILENAME stromg value";
		return NULL;
	}

	smarg = mail_search_mime_build_new(ctx, type);
	smarg->value.str = value;
	return smarg;
}

static struct mail_search_mime_arg *
mail_search_mime_parent(struct mail_search_mime_build_context *ctx)
{
	struct mail_search_mime_arg *smarg, *subargs;

	smarg = mail_search_mime_build_new(ctx, SEARCH_MIME_PARENT);
	if (mail_search_mime_build_key(ctx, smarg, &subargs) < 0)
		return NULL;
	if (subargs == smarg)
		smarg->value.subargs = NULL;
	else if (subargs->type == SEARCH_MIME_SUB)
		smarg->value.subargs = subargs->value.subargs;
	else
		smarg->value.subargs = subargs;
	return smarg;
}

static struct mail_search_mime_arg *
mail_search_mime_child(struct mail_search_mime_build_context *ctx)
{
	struct mail_search_mime_arg *smarg, *subargs;

	smarg = mail_search_mime_build_new(ctx, SEARCH_MIME_CHILD);
	if (mail_search_mime_build_key(ctx, smarg, &subargs) < 0)
		return NULL;
	if (subargs == smarg)
		smarg->value.subargs = NULL;
	else if (subargs->type == SEARCH_MIME_SUB)
		smarg->value.subargs = subargs->value.subargs;
	else
		smarg->value.subargs = subargs;
	return smarg;
}

static struct mail_search_mime_arg *
mail_search_mime_exists(struct mail_search_mime_build_context *ctx)
{
	if (ctx->parent == NULL ||
		(ctx->parent->type != SEARCH_MIME_PARENT &&
			ctx->parent->type != SEARCH_MIME_CHILD)) {
		ctx->ctx->_error = "EXISTS key can only be used with PARENT or CHILD";
		return NULL;
	}
	return ctx->parent;
}

static const struct mail_search_mime_register_arg
mime_register_args[] = {
	/* argument set operations */
	{ "NOT", mail_search_mime_not },
	{ "OR", mail_search_mime_or },

	/* dates */
	{ "SENTBEFORE", mail_search_mime_sentbefore },
	{ "SENTON", mail_search_mime_senton },
	{ "SENTSINCE", mail_search_mime_sentsince },

	/* size */
	{ "SIZE", mail_search_mime_size },

	/* part properties */
	{ "DESCRIPTION", mail_search_mime_description },
	{ "DISPOSITION", mail_search_mime_disposition },
	{ "ENCODING", mail_search_mime_encoding },
	{ "ID", mail_search_mime_id },
	{ "LANGUAGE", mail_search_mime_language },
	{ "LOCATION", mail_search_mime_location },
	{ "MD5", mail_search_mime_md5 },

	/* content-type */
	{ "TYPE", mail_search_mime_type },
	{ "SUBTYPE", mail_search_mime_subtype },
	{ "PARAM", mail_search_mime_param },

	/* headers */
	{ "HEADER", mail_search_mime_header },

	/* message */
	{ "BCC", mail_search_mime_bcc },
	{ "CC", mail_search_mime_cc },
	{ "FROM", mail_search_mime_from },
	{ "IN-REPLY-TO", mail_search_mime_in_reply_to },
	{ "MESSAGE-ID", mail_search_mime_message_id },
	{ "REPLY-TO", mail_search_mime_reply_to },
	{ "SENDER", mail_search_mime_sender },
	{ "SUBJECT", mail_search_mime_subject },
	{ "TO", mail_search_mime_to },

	/* body */
	{ "BODY", mail_search_mime_body },
	{ "TEXT", mail_search_mime_text },

	/* position */
	{ "DEPTH", mail_search_mime_depth },
	{ "INDEX", mail_search_mime_index },

	/* relations */
	{ "PARENT", mail_search_mime_parent },
	{ "CHILD", mail_search_mime_child },
	{ "EXISTS", mail_search_mime_exists },

	/* filename */
	{ "FILENAME", mail_search_mime_filename },
};

static void
mail_search_register_add_default(void)
{
	mail_search_mime_register_add(mime_register_args,
			 N_ELEMENTS(mime_register_args));
}
