/* Copyright (c) 2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "imap-date.h"
#include "imap-arg.h"
#include "imap-seqset.h"
#include "imap-util.h"
#include "mail-search-register.h"
#include "mail-search-build.h"

#include <stdlib.h>

struct mail_search_register *mail_search_register_imap;

static struct mail_search_arg *
imap_search_fallback(struct mail_search_build_context *ctx,
		     const char *key,
		     const struct imap_arg **imap_args ATTR_UNUSED)
{
	struct mail_search_arg *sarg;

	if (*key == '*' || (*key >= '0' && *key <= '9')) {
		/* <message-set> */
		sarg = mail_search_build_new(ctx, SEARCH_SEQSET);
		p_array_init(&sarg->value.seqset, ctx->pool, 16);
		if (imap_seq_set_parse(key, &sarg->value.seqset) < 0) {
			ctx->error = "Invalid messageset";
			return NULL;
		}
		return sarg;
	}
	ctx->error = p_strconcat(ctx->pool, "Unknown argument ", key, NULL);
	return NULL;
}

static struct mail_search_arg *
imap_search_not(struct mail_search_build_context *ctx,
		const struct imap_arg **imap_args)
{
	struct mail_search_arg *sarg;

	sarg = mail_search_build_next(ctx, ctx->parent, imap_args);
	if (sarg != NULL)
		sarg->not = !sarg->not;
	return sarg;
}

static struct mail_search_arg *
imap_search_or(struct mail_search_build_context *ctx,
	       const struct imap_arg **imap_args)
{
	struct mail_search_arg *sarg, **subargs;

	/* <search-key1> <search-key2> */
	sarg = mail_search_build_new(ctx, SEARCH_OR);

	subargs = &sarg->value.subargs;
	for (;;) {
		*subargs = mail_search_build_next(ctx, sarg, imap_args);
		if (*subargs == NULL)
			return NULL;
		subargs = &(*subargs)->next;

		/* <key> OR <key> OR ... <key> - put them all
		   under one SEARCH_OR list. */
		if (!imap_arg_atom_equals(*imap_args, "OR"))
			break;

		*imap_args += 1;
	}

	*subargs = mail_search_build_next(ctx, sarg, imap_args);
	if (*subargs == NULL)
		return NULL;
	return sarg;
}

#define CALLBACK_STR(_func, _type) \
static struct mail_search_arg *\
imap_search_##_func(struct mail_search_build_context *ctx, \
                    const struct imap_arg **imap_args) \
{ \
	return mail_search_build_str(ctx, imap_args, _type); \
}
static struct mail_search_arg *
imap_search_all(struct mail_search_build_context *ctx,
		const struct imap_arg **imap_args ATTR_UNUSED)
{ 
	return mail_search_build_new(ctx, SEARCH_ALL);
}

static struct mail_search_arg *
imap_search_uid(struct mail_search_build_context *ctx,
		const struct imap_arg **imap_args ATTR_UNUSED)
{
	struct mail_search_arg *sarg;

	/* <message set> */
	sarg = mail_search_build_str(ctx, imap_args, SEARCH_UIDSET);
	if (sarg == NULL)
		return NULL;

	p_array_init(&sarg->value.seqset, ctx->pool, 16);
	if (strcmp(sarg->value.str, "$") == 0) {
		/* SEARCHRES: delay initialization */
	} else {
		if (imap_seq_set_parse(sarg->value.str,
				       &sarg->value.seqset) < 0) {
			ctx->error = "Invalid UID messageset";
			return NULL;
		}
	}
	return sarg;
}

#define CALLBACK_FLAG(_func, _flag, _not) \
static struct mail_search_arg *\
imap_search_##_func(struct mail_search_build_context *ctx, \
                    const struct imap_arg **imap_args ATTR_UNUSED) \
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
imap_search_new(struct mail_search_build_context *ctx,
		const struct imap_arg **imap_args ATTR_UNUSED)
{
	struct mail_search_arg *sarg;

	/* NEW == (RECENT UNSEEN) */
	sarg = mail_search_build_new(ctx, SEARCH_SUB);
	sarg->value.subargs = imap_search_recent(ctx, NULL);
	sarg->value.subargs->next = imap_search_unseen(ctx, NULL);
	return sarg;
}

CALLBACK_STR(keyword, SEARCH_KEYWORDS);

static struct mail_search_arg *
imap_search_unkeyword(struct mail_search_build_context *ctx,
		      const struct imap_arg **imap_args)
{
	struct mail_search_arg *sarg;

	sarg = imap_search_keyword(ctx, imap_args);
	if (sarg != NULL)
		sarg->not = TRUE;
	return sarg;
}

static struct mail_search_arg *
arg_new_date(struct mail_search_build_context *ctx,
	     const struct imap_arg **imap_args,
	     enum mail_search_arg_type type,
	     enum mail_search_date_type date_type)
{
	struct mail_search_arg *sarg;
	const char *value;

	sarg = mail_search_build_new(ctx, type);
	if (mail_search_build_next_astring(ctx, imap_args, &value) < 0)
		return NULL;
	if (!imap_parse_date(value, &sarg->value.time)) {
		ctx->error = "Invalid search date parameter";
		return NULL;
	}
	sarg->value.date_type = date_type;
	return sarg;
}

#define CALLBACK_DATE(_func, _type, _date_type) \
static struct mail_search_arg *\
imap_search_##_func(struct mail_search_build_context *ctx, \
                    const struct imap_arg **imap_args) \
{ \
	return arg_new_date(ctx, imap_args, _type, _date_type); \
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
	     const struct imap_arg **imap_args,
	     enum mail_search_arg_type type)
{
	struct mail_search_arg *sarg;
	const char *value;

	sarg = mail_search_build_new(ctx, type);
	if (mail_search_build_next_astring(ctx, imap_args, &value) < 0)
		return NULL;

	if (str_to_uoff(value, &sarg->value.size) < 0) {
		ctx->error = "Invalid search size parameter";
		return NULL;
	}
	return sarg;
}

static struct mail_search_arg *
imap_search_larger(struct mail_search_build_context *ctx,
		   const struct imap_arg **imap_args)
{ 
	return arg_new_size(ctx, imap_args, SEARCH_LARGER);
}

static struct mail_search_arg *
imap_search_smaller(struct mail_search_build_context *ctx,
		    const struct imap_arg **imap_args)
{ 
	return arg_new_size(ctx, imap_args, SEARCH_SMALLER);
}

static struct mail_search_arg *
arg_new_header(struct mail_search_build_context *ctx,
	       const struct imap_arg **imap_args,
	       enum mail_search_arg_type type, const char *hdr_name)
{
	struct mail_search_arg *sarg;
	const char *value;

	sarg = mail_search_build_new(ctx, type);
	if (mail_search_build_next_astring(ctx, imap_args, &value) < 0)
		return NULL;

	sarg->hdr_field_name = p_strdup(ctx->pool, hdr_name);
	sarg->value.str = p_strdup(ctx->pool, value);
	return sarg;
}

#define CALLBACK_HDR(_name, _type) \
static struct mail_search_arg *\
imap_search_##_name(struct mail_search_build_context *ctx, \
                    const struct imap_arg **imap_args) \
{ \
	return arg_new_header(ctx, imap_args, _type, #_name); \
}
CALLBACK_HDR(bcc, SEARCH_HEADER_ADDRESS);
CALLBACK_HDR(cc, SEARCH_HEADER_ADDRESS);
CALLBACK_HDR(from, SEARCH_HEADER_ADDRESS);
CALLBACK_HDR(to, SEARCH_HEADER_ADDRESS);
CALLBACK_HDR(subject, SEARCH_HEADER_COMPRESS_LWSP);

static struct mail_search_arg *
imap_search_header(struct mail_search_build_context *ctx,
		   const struct imap_arg **imap_args)
{
	const char *value;

	/* <field-name> <string> */
	if (IMAP_ARG_IS_EOL(*imap_args)) {
		ctx->error = "Missing parameter for HEADER";
		return NULL;
	}
	if (!imap_arg_get_astring(*imap_args, &value)) {
		ctx->error = "Invalid parameter for HEADER";
		return NULL;
	}

	*imap_args += 1;
	return arg_new_header(ctx, imap_args, SEARCH_HEADER,
			      t_str_ucase(value));
}

#define CALLBACK_BODY(_func, _type) \
static struct mail_search_arg *\
imap_search_##_func(struct mail_search_build_context *ctx, \
                    const struct imap_arg **imap_args) \
{ \
	const char *value; \
	if (imap_arg_get_astring(*imap_args, &value) && *value == '\0') { \
		/* optimization: BODY "" matches everything */ \
		*imap_args += 1; \
		return mail_search_build_new(ctx, SEARCH_ALL); \
	} \
	return mail_search_build_str(ctx, imap_args, _type); \
}
CALLBACK_BODY(body, SEARCH_BODY);
CALLBACK_BODY(text, SEARCH_TEXT);
CALLBACK_BODY(x_body_fast, SEARCH_BODY_FAST);
CALLBACK_BODY(x_text_fast, SEARCH_TEXT_FAST);

static struct mail_search_arg *
arg_new_interval(struct mail_search_build_context *ctx,
		 const struct imap_arg **imap_args,
		 enum mail_search_arg_type type)
{
	struct mail_search_arg *sarg;
	const char *value;
	uint32_t interval;

	sarg = mail_search_build_new(ctx, type);
	if (mail_search_build_next_astring(ctx, imap_args, &value) < 0)
		return NULL;

	if (str_to_uint32(value, &interval) < 0 || interval == 0) {
		ctx->error = "Invalid search interval parameter";
		return NULL;
	}
	sarg->value.search_flags = MAIL_SEARCH_ARG_FLAG_USE_TZ;
	sarg->value.time = ioloop_time - interval;
	return sarg;
}

static struct mail_search_arg *
imap_search_older(struct mail_search_build_context *ctx,
		  const struct imap_arg **imap_args)
{
	struct mail_search_arg *sarg;

	sarg = arg_new_interval(ctx, imap_args, SEARCH_BEFORE);
	/* we need to match also equal, but SEARCH_BEFORE compares with "<" */
	sarg->value.time++;
	return sarg;
}

static struct mail_search_arg *
imap_search_younger(struct mail_search_build_context *ctx,
		    const struct imap_arg **imap_args)
{
	return arg_new_interval(ctx, imap_args, SEARCH_SINCE);
}

static int
arg_modseq_set_name(struct mail_search_build_context *ctx,
		    struct mail_search_arg *sarg, const char *name)
{
	name = t_str_lcase(name);
	if (strncmp(name, "/flags/", 7) != 0) {
		ctx->error = "Invalid MODSEQ entry";
		return -1;
	}
	name += 7;

	if (*name == '\\') {
		/* system flag */
		sarg->value.flags = imap_parse_system_flag(name);
		if (sarg->value.flags == 0 ||
		    sarg->value.flags == MAIL_RECENT) {
			ctx->error = "Invalid MODSEQ system flag";
			return -1;
		}
		return 0;
	}
	sarg->value.str = p_strdup(ctx->pool, name);
	return 0;
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
		ctx->error = "Invalid MODSEQ type";
		return -1;
	}
	return 0;
}

static struct mail_search_arg *
imap_search_modseq(struct mail_search_build_context *ctx,
		   const struct imap_arg **imap_args)
{
	struct mail_search_arg *sarg;
	const char *value;

	/* [<name> <type>] <modseq> */
	sarg = mail_search_build_new(ctx, SEARCH_MODSEQ);
	if (mail_search_build_next_astring(ctx, imap_args, &value) < 0)
		return NULL;

	sarg->value.modseq = p_new(ctx->pool, struct mail_search_modseq, 1);
	if ((*imap_args)[-1].type == IMAP_ARG_STRING) {
		/* <name> <type> */
		if (arg_modseq_set_name(ctx, sarg, value) < 0)
			return NULL;

		if (mail_search_build_next_astring(ctx, imap_args, &value) < 0)
			return NULL;
		if (arg_modseq_set_type(ctx, sarg->value.modseq, value) < 0)
			return NULL;

		if (mail_search_build_next_astring(ctx, imap_args, &value) < 0)
			return NULL;
	}
	if (str_to_uint64(value, &sarg->value.modseq->modseq) < 0) {
		ctx->error = "Invalid MODSEQ value";
		return NULL;
	}
	return sarg;
}

static struct mail_search_arg *
imap_search_last_result(struct mail_search_build_context *ctx,
			const struct imap_arg **imap_args ATTR_UNUSED)
{
	struct mail_search_arg *sarg;

	/* SEARCHRES: delay initialization */
	sarg = mail_search_build_new(ctx, SEARCH_UIDSET);
	sarg->value.str = "$";
	p_array_init(&sarg->value.seqset, ctx->pool, 16);
	return sarg;
}

static struct mail_search_arg *
imap_search_inthread(struct mail_search_build_context *ctx,
		     const struct imap_arg **imap_args)
{
	struct mail_search_arg *sarg;

	/* <algorithm> <search key> */
	enum mail_thread_type thread_type;
	const char *algorithm;

	if (!imap_arg_get_atom(*imap_args, &algorithm)) {
		ctx->error = "Invalid parameter for INTHREAD";
		return NULL;
	}

	if (!mail_thread_type_parse(algorithm, &thread_type)) {
		ctx->error = "Unknown thread algorithm";
		return NULL;
	}
	*imap_args += 1;

	sarg = mail_search_build_new(ctx, SEARCH_INTHREAD);
	sarg->value.thread_type = thread_type;
	sarg->value.subargs = mail_search_build_next(ctx, sarg, imap_args);
	if (sarg->value.subargs == NULL)
		return NULL;
	return sarg;
}

CALLBACK_STR(x_guid, SEARCH_GUID);
CALLBACK_STR(x_mailbox, SEARCH_MAILBOX);

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

struct mail_search_register *mail_search_register_init_imap(void)
{
	struct mail_search_register *reg;

	reg = mail_search_register_init();
	mail_search_register_add(reg, imap_register_args,
				 N_ELEMENTS(imap_register_args));
	mail_search_register_fallback(reg, imap_search_fallback);
	return reg;
}
