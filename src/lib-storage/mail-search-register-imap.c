/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "imap-date.h"
#include "imap-seqset.h"
#include "imap-util.h"
#include "mail-search-register.h"
#include "mail-search-parser.h"
#include "mail-search-build.h"

#include <stdlib.h>

struct mail_search_register *mail_search_register_imap;

static struct mail_search_arg *
imap_search_fallback(struct mail_search_build_context *ctx,
		     const char *key)
{
	struct mail_search_arg *sarg;

	if (*key == '*' || (*key >= '0' && *key <= '9')) {
		/* <message-set> */
		sarg = mail_search_build_new(ctx, SEARCH_SEQSET);
		p_array_init(&sarg->value.seqset, ctx->pool, 16);
		if (imap_seq_set_parse(key, &sarg->value.seqset) < 0) {
			ctx->_error = "Invalid messageset";
			return NULL;
		}
		return sarg;
	}
	ctx->_error = p_strconcat(ctx->pool, "Unknown argument ", key, NULL);
	return NULL;
}

static struct mail_search_arg *
imap_search_not(struct mail_search_build_context *ctx)
{
	struct mail_search_arg *sarg;

	if (mail_search_build_key(ctx, ctx->parent, &sarg) < 0)
		return NULL;

	sarg->not = !sarg->not;
	return sarg;
}

static struct mail_search_arg *
imap_search_or(struct mail_search_build_context *ctx)
{
	struct mail_search_arg *sarg, **subargs;

	/* <search-key1> <search-key2> */
	sarg = mail_search_build_new(ctx, SEARCH_OR);

	subargs = &sarg->value.subargs;
	do {
		if (mail_search_build_key(ctx, sarg, subargs) < 0)
			return NULL;
		subargs = &(*subargs)->next;

		/* <key> OR <key> OR ... <key> - put them all
		   under one SEARCH_OR list. */
	} while (mail_search_parse_skip_next(ctx->parser, "OR"));

	if (mail_search_build_key(ctx, sarg, subargs) < 0)
		return NULL;
	return sarg;
}

#define CALLBACK_STR(_func, _type) \
static struct mail_search_arg *\
imap_search_##_func(struct mail_search_build_context *ctx) \
{ \
	return mail_search_build_str(ctx, _type); \
}
static struct mail_search_arg *
imap_search_all(struct mail_search_build_context *ctx)
{ 
	return mail_search_build_new(ctx, SEARCH_ALL);
}

static struct mail_search_arg *
imap_search_uid(struct mail_search_build_context *ctx)
{
	struct mail_search_arg *sarg;

	/* <message set> */
	sarg = mail_search_build_str(ctx, SEARCH_UIDSET);
	if (sarg == NULL)
		return NULL;

	p_array_init(&sarg->value.seqset, ctx->pool, 16);
	if (strcmp(sarg->value.str, "$") == 0) {
		/* SEARCHRES: delay initialization */
	} else {
		if (imap_seq_set_parse(sarg->value.str,
				       &sarg->value.seqset) < 0) {
			ctx->_error = "Invalid UID messageset";
			return NULL;
		}
	}
	return sarg;
}

#define CALLBACK_FLAG(_func, _flag, _not) \
static struct mail_search_arg *\
imap_search_##_func(struct mail_search_build_context *ctx) \
{ \
	struct mail_search_arg *sarg; \
	sarg = mail_search_build_new(ctx, SEARCH_FLAGS); \
	sarg->value.flags = _flag; \
	sarg->not = _not; \
	return sarg; \
}
CALLBACK_FLAG(answered, MAIL_ANSWERED, FALSE);
CALLBACK_FLAG(unanswered, MAIL_ANSWERED, TRUE);
CALLBACK_FLAG(deleted, MAIL_DELETED, FALSE);
CALLBACK_FLAG(undeleted, MAIL_DELETED, TRUE);
CALLBACK_FLAG(draft, MAIL_DRAFT, FALSE);
CALLBACK_FLAG(undraft, MAIL_DRAFT, TRUE);
CALLBACK_FLAG(flagged, MAIL_FLAGGED, FALSE);
CALLBACK_FLAG(unflagged, MAIL_FLAGGED, TRUE);
CALLBACK_FLAG(seen, MAIL_SEEN, FALSE);
CALLBACK_FLAG(unseen, MAIL_SEEN, TRUE);
CALLBACK_FLAG(recent, MAIL_RECENT, FALSE);
CALLBACK_FLAG(old, MAIL_RECENT, TRUE);

static struct mail_search_arg *
imap_search_new(struct mail_search_build_context *ctx)
{
	struct mail_search_arg *sarg;

	/* NEW == (RECENT UNSEEN) */
	sarg = mail_search_build_new(ctx, SEARCH_SUB);
	sarg->value.subargs = imap_search_recent(ctx);
	sarg->value.subargs->next = imap_search_unseen(ctx);
	return sarg;
}

CALLBACK_STR(keyword, SEARCH_KEYWORDS);

static struct mail_search_arg *
imap_search_unkeyword(struct mail_search_build_context *ctx)
{
	struct mail_search_arg *sarg;

	sarg = imap_search_keyword(ctx);
	if (sarg != NULL)
		sarg->not = TRUE;
	return sarg;
}

static struct mail_search_arg *
arg_new_date(struct mail_search_build_context *ctx,
	     enum mail_search_arg_type type,
	     enum mail_search_date_type date_type)
{
	struct mail_search_arg *sarg;
	const char *value;

	sarg = mail_search_build_new(ctx, type);
	if (mail_search_parse_string(ctx->parser, &value) < 0)
		return NULL;
	if (!imap_parse_date(value, &sarg->value.time)) {
		ctx->_error = "Invalid search date parameter";
		return NULL;
	}
	sarg->value.date_type = date_type;
	return sarg;
}

#define CALLBACK_DATE(_func, _type, _date_type) \
static struct mail_search_arg *\
imap_search_##_func(struct mail_search_build_context *ctx) \
{ \
	return arg_new_date(ctx, _type, _date_type); \
}
CALLBACK_DATE(before, SEARCH_BEFORE, MAIL_SEARCH_DATE_TYPE_RECEIVED);
CALLBACK_DATE(on, SEARCH_ON, MAIL_SEARCH_DATE_TYPE_RECEIVED);
CALLBACK_DATE(since, SEARCH_SINCE, MAIL_SEARCH_DATE_TYPE_RECEIVED);

CALLBACK_DATE(sentbefore, SEARCH_BEFORE, MAIL_SEARCH_DATE_TYPE_SENT);
CALLBACK_DATE(senton, SEARCH_ON, MAIL_SEARCH_DATE_TYPE_SENT);
CALLBACK_DATE(sentsince, SEARCH_SINCE, MAIL_SEARCH_DATE_TYPE_SENT);

CALLBACK_DATE(x_savedbefore, SEARCH_BEFORE, MAIL_SEARCH_DATE_TYPE_SAVED);
CALLBACK_DATE(x_savedon, SEARCH_ON, MAIL_SEARCH_DATE_TYPE_SAVED);
CALLBACK_DATE(x_savedsince, SEARCH_SINCE, MAIL_SEARCH_DATE_TYPE_SAVED);

static struct mail_search_arg *
arg_new_size(struct mail_search_build_context *ctx,
	     enum mail_search_arg_type type)
{
	struct mail_search_arg *sarg;
	const char *value;

	sarg = mail_search_build_new(ctx, type);
	if (mail_search_parse_string(ctx->parser, &value) < 0)
		return NULL;

	if (str_to_uoff(value, &sarg->value.size) < 0) {
		ctx->_error = "Invalid search size parameter";
		return NULL;
	}
	return sarg;
}

static struct mail_search_arg *
imap_search_larger(struct mail_search_build_context *ctx)
{ 
	return arg_new_size(ctx, SEARCH_LARGER);
}

static struct mail_search_arg *
imap_search_smaller(struct mail_search_build_context *ctx)
{ 
	return arg_new_size(ctx, SEARCH_SMALLER);
}

static struct mail_search_arg *
arg_new_header(struct mail_search_build_context *ctx,
	       enum mail_search_arg_type type, const char *hdr_name)
{
	struct mail_search_arg *sarg;
	const char *value;

	sarg = mail_search_build_new(ctx, type);
	if (mail_search_parse_string(ctx->parser, &value) < 0)
		return NULL;

	sarg->hdr_field_name = p_strdup(ctx->pool, hdr_name);
	sarg->value.str = p_strdup(ctx->pool, value);
	return sarg;
}

#define CALLBACK_HDR(_name, _type) \
static struct mail_search_arg *\
imap_search_##_name(struct mail_search_build_context *ctx) \
{ \
	return arg_new_header(ctx, _type, #_name); \
}
CALLBACK_HDR(bcc, SEARCH_HEADER_ADDRESS);
CALLBACK_HDR(cc, SEARCH_HEADER_ADDRESS);
CALLBACK_HDR(from, SEARCH_HEADER_ADDRESS);
CALLBACK_HDR(to, SEARCH_HEADER_ADDRESS);
CALLBACK_HDR(subject, SEARCH_HEADER_COMPRESS_LWSP);

static struct mail_search_arg *
imap_search_header(struct mail_search_build_context *ctx)
{
	const char *hdr_name;

	/* <hdr-name> <string> */
	if (mail_search_parse_string(ctx->parser, &hdr_name) < 0)
		return NULL;

	return arg_new_header(ctx, SEARCH_HEADER, t_str_ucase(hdr_name));
}

#define CALLBACK_BODY(_func, _type) \
static struct mail_search_arg *\
imap_search_##_func(struct mail_search_build_context *ctx) \
{ \
	if (mail_search_parse_skip_next(ctx->parser, "")) { \
		/* optimization: BODY "" matches everything */ \
		return mail_search_build_new(ctx, SEARCH_ALL); \
	} \
	return mail_search_build_str(ctx, _type); \
}
CALLBACK_BODY(body, SEARCH_BODY);
CALLBACK_BODY(text, SEARCH_TEXT);
CALLBACK_BODY(x_body_fast, SEARCH_BODY_FAST);
CALLBACK_BODY(x_text_fast, SEARCH_TEXT_FAST);

static struct mail_search_arg *
arg_new_interval(struct mail_search_build_context *ctx,
		 enum mail_search_arg_type type)
{
	struct mail_search_arg *sarg;
	const char *value;
	uint32_t interval;

	sarg = mail_search_build_new(ctx, type);
	if (mail_search_parse_string(ctx->parser, &value) < 0)
		return NULL;

	if (str_to_uint32(value, &interval) < 0 || interval == 0) {
		ctx->_error = "Invalid search interval parameter";
		return NULL;
	}
	sarg->value.search_flags = MAIL_SEARCH_ARG_FLAG_USE_TZ;
	sarg->value.time = ioloop_time - interval;
	sarg->value.date_type = MAIL_SEARCH_DATE_TYPE_RECEIVED;
	return sarg;
}

static struct mail_search_arg *
imap_search_older(struct mail_search_build_context *ctx)
{
	struct mail_search_arg *sarg;

	sarg = arg_new_interval(ctx, SEARCH_BEFORE);
	if (sarg == NULL)
		return NULL;

	/* we need to match also equal, but SEARCH_BEFORE compares with "<" */
	sarg->value.time++;
	return sarg;
}

static struct mail_search_arg *
imap_search_younger(struct mail_search_build_context *ctx)
{
	return arg_new_interval(ctx, SEARCH_SINCE);
}

static int
arg_modseq_set_type(struct mail_search_build_context *ctx,
		    struct mail_search_modseq *modseq, const char *name)
{
	if (strcasecmp(name, "all") == 0)
		modseq->type = MAIL_SEARCH_MODSEQ_TYPE_ANY;
	else if (strcasecmp(name, "priv") == 0)
		modseq->type = MAIL_SEARCH_MODSEQ_TYPE_PRIVATE;
	else if (strcasecmp(name, "shared") == 0)
		modseq->type = MAIL_SEARCH_MODSEQ_TYPE_SHARED;
	else {
		ctx->_error = "Invalid MODSEQ type";
		return -1;
	}
	return 0;
}

static int
arg_modseq_set_ext(struct mail_search_build_context *ctx,
		   struct mail_search_arg *sarg, const char *name)
{
	const char *value;

	name = t_str_lcase(name);
	if (strncmp(name, "/flags/", 7) != 0)
		return 0;
	name += 7;

	/* set name */
	if (*name == '\\') {
		/* system flag */
		sarg->value.flags = imap_parse_system_flag(name);
		if (sarg->value.flags == 0 ||
		    sarg->value.flags == MAIL_RECENT) {
			ctx->_error = "Invalid MODSEQ system flag";
			return -1;
		}
	} else {
		sarg->value.str = p_strdup(ctx->pool, name);
	}

	/* set type */
	if (mail_search_parse_string(ctx->parser, &value) < 0)
		return -1;
	if (arg_modseq_set_type(ctx, sarg->value.modseq, value) < 0)
		return -1;
	return 1;
}

static struct mail_search_arg *
imap_search_modseq(struct mail_search_build_context *ctx)
{
	struct mail_search_arg *sarg;
	const char *value;
	int ret;

	/* [<name> <type>] <modseq> */
	sarg = mail_search_build_new(ctx, SEARCH_MODSEQ);
	sarg->value.modseq = p_new(ctx->pool, struct mail_search_modseq, 1);

	if (mail_search_parse_string(ctx->parser, &value) < 0)
		return NULL;

	if ((ret = arg_modseq_set_ext(ctx, sarg, value)) < 0)
		return NULL;
	if (ret > 0) {
		/* extension data used */
		if (mail_search_parse_string(ctx->parser, &value) < 0)
			return NULL;
	}

	if (str_to_uint64(value, &sarg->value.modseq->modseq) < 0) {
		ctx->_error = "Invalid MODSEQ value";
		return NULL;
	}
	return sarg;
}

static struct mail_search_arg *
imap_search_last_result(struct mail_search_build_context *ctx)
{
	struct mail_search_arg *sarg;

	/* SEARCHRES: delay initialization */
	sarg = mail_search_build_new(ctx, SEARCH_UIDSET);
	sarg->value.str = "$";
	p_array_init(&sarg->value.seqset, ctx->pool, 16);
	return sarg;
}

static struct mail_search_arg *
imap_search_inthread(struct mail_search_build_context *ctx)
{
	struct mail_search_arg *sarg;

	/* <algorithm> <search key> */
	enum mail_thread_type thread_type;
	const char *algorithm;

	if (mail_search_parse_string(ctx->parser, &algorithm) < 0)
		return NULL;
	if (!mail_thread_type_parse(algorithm, &thread_type)) {
		ctx->_error = "Unknown thread algorithm";
		return NULL;
	}

	sarg = mail_search_build_new(ctx, SEARCH_INTHREAD);
	sarg->value.thread_type = thread_type;
	if (mail_search_build_key(ctx, sarg, &sarg->value.subargs) < 0)
		return NULL;
	return sarg;
}

CALLBACK_STR(x_guid, SEARCH_GUID);
CALLBACK_STR(x_mailbox, SEARCH_MAILBOX_GLOB);

const struct mail_search_register_arg imap_register_args[] = {
	/* argument set operations */
	{ "NOT", imap_search_not },
	{ "OR", imap_search_or },

	/* message sets */
	{ "ALL", imap_search_all },
	{ "UID", imap_search_uid },

	/* flags */
	{ "ANSWERED", imap_search_answered },
	{ "UNANSWERED", imap_search_unanswered },
	{ "DELETED", imap_search_deleted },
	{ "UNDELETED", imap_search_undeleted },
	{ "DRAFT", imap_search_draft },
	{ "UNDRAFT", imap_search_undraft },
	{ "FLAGGED", imap_search_flagged },
	{ "UNFLAGGED", imap_search_unflagged },
	{ "SEEN", imap_search_seen },
	{ "UNSEEN", imap_search_unseen },
	{ "RECENT", imap_search_recent },
	{ "OLD", imap_search_old },
	{ "NEW", imap_search_new },

	/* keywords */
	{ "KEYWORD", imap_search_keyword },
	{ "UNKEYWORD", imap_search_unkeyword },

	/* dates */
	{ "BEFORE", imap_search_before },
	{ "ON", imap_search_on },
	{ "SINCE", imap_search_since },
	{ "SENTBEFORE", imap_search_sentbefore },
	{ "SENTON", imap_search_senton },
	{ "SENTSINCE", imap_search_sentsince },
	{ "X-SAVEDBEFORE", imap_search_x_savedbefore },
	{ "X-SAVEDON", imap_search_x_savedon },
	{ "X-SAVEDSINCE", imap_search_x_savedsince },

	/* sizes */
	{ "LARGER", imap_search_larger },
	{ "SMALLER", imap_search_smaller },

	/* headers */
	{ "BCC", imap_search_bcc },
	{ "CC", imap_search_cc },
	{ "FROM", imap_search_from },
	{ "TO", imap_search_to },
	{ "SUBJECT", imap_search_subject },
	{ "HEADER", imap_search_header },

	/* body */
	{ "BODY", imap_search_body },
	{ "TEXT", imap_search_text },
	{ "X-BODY-FAST", imap_search_x_body_fast },
	{ "X-TEXT-FAST", imap_search_x_text_fast },

	/* WITHIN extension: */
	{ "OLDER", imap_search_older },
	{ "YOUNGER", imap_search_younger },

	/* CONDSTORE extension: */
	{ "MODSEQ", imap_search_modseq },

	/* SEARCHRES extension: */
	{ "$", imap_search_last_result },

	/* Other Dovecot extensions: */
	{ "INTHREAD", imap_search_inthread },
	{ "X-GUID", imap_search_x_guid },
	{ "X-MAILBOX", imap_search_x_mailbox }
};

static struct mail_search_register *mail_search_register_init_imap(void)
{
	struct mail_search_register *reg;

	reg = mail_search_register_init();
	mail_search_register_add(reg, imap_register_args,
				 N_ELEMENTS(imap_register_args));
	mail_search_register_fallback(reg, imap_search_fallback);
	return reg;
}

struct mail_search_register *
mail_search_register_get_imap(void)
{
	if (mail_search_register_imap == NULL)
		mail_search_register_imap = mail_search_register_init_imap();
	return mail_search_register_imap;
}
