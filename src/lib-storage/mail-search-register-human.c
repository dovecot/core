/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "str.h"
#include "imap-utf7.h"
#include "settings-parser.h"
#include "imap-date.h"
#include "mail-search-register.h"
#include "mail-search-parser.h"
#include "mail-search-build.h"

#include <time.h>
#include <ctype.h>

struct mail_search_register *mail_search_register_human;

static struct mail_search_arg *
human_search_or(struct mail_search_build_context *ctx)
{
	struct mail_search_arg *sarg;

	/* this changes the parent arg to be an OR block instead of AND block */
	ctx->parent->type = SEARCH_OR;
	if (mail_search_build_key(ctx, ctx->parent, &sarg) < 0)
		return NULL;
	return sarg;
}

static struct mail_search_arg *
arg_new_human_date(struct mail_search_build_context *ctx,
		   enum mail_search_arg_type type,
		   enum mail_search_date_type date_type)
{
	struct mail_search_arg *sarg;
	const char *value, *error;
	struct tm tm;
	unsigned int secs;
	unsigned long unixtime;

	sarg = mail_search_build_new(ctx, type);
	if (mail_search_parse_string(ctx->parser, &value) < 0)
		return NULL;

	/* a) yyyy-mm-dd
	   b) imap date
	   c) unix timestamp
	   d) interval (e.g. n days) */
	if (i_isdigit(value[0]) && i_isdigit(value[1]) &&
	    i_isdigit(value[2]) && i_isdigit(value[3]) && value[4] == '-' &&
	    i_isdigit(value[5]) && i_isdigit(value[6]) && value[7] == '-' &&
	    i_isdigit(value[8]) && i_isdigit(value[9]) && value[10] == '\0') {
		memset(&tm, 0, sizeof(tm));
		tm.tm_year = (value[0]-'0') * 1000 + (value[1]-'0') * 100 +
			(value[2]-'0') * 10 + (value[3]-'0') - 1900;
		tm.tm_mon = (value[5]-'0') * 10 + (value[6]-'0') - 1;
		tm.tm_mday = (value[8]-'0') * 10 + (value[9]-'0');
		sarg->value.time = mktime(&tm);
	} else if (imap_parse_date(value, &sarg->value.time)) {
		/* imap date */
	} else if (str_to_ulong(value, &unixtime) == 0) {
		sarg->value.time = unixtime;
	} else if (settings_get_time(value, &secs, &error) == 0) {
		sarg->value.time = ioloop_time - secs;
	} else {
		sarg->value.time = (time_t)-1;
	}
	sarg->value.search_flags = MAIL_SEARCH_ARG_FLAG_USE_TZ;

	if (sarg->value.time == (time_t)-1) {
		ctx->_error = p_strconcat(ctx->pool,
			"Invalid search date parameter: ", value, NULL);
		return NULL;
	}
	sarg->value.date_type = date_type;
	return sarg;
}

#define CALLBACK_DATE(_func, _type, _date_type) \
static struct mail_search_arg *\
human_search_##_func(struct mail_search_build_context *ctx) \
{ \
	return arg_new_human_date(ctx, _type, _date_type); \
}
CALLBACK_DATE(before, SEARCH_BEFORE, MAIL_SEARCH_DATE_TYPE_RECEIVED);
CALLBACK_DATE(on, SEARCH_ON, MAIL_SEARCH_DATE_TYPE_RECEIVED);
CALLBACK_DATE(since, SEARCH_SINCE, MAIL_SEARCH_DATE_TYPE_RECEIVED);

CALLBACK_DATE(sentbefore, SEARCH_BEFORE, MAIL_SEARCH_DATE_TYPE_SENT);
CALLBACK_DATE(senton, SEARCH_ON, MAIL_SEARCH_DATE_TYPE_SENT);
CALLBACK_DATE(sentsince, SEARCH_SINCE, MAIL_SEARCH_DATE_TYPE_SENT);

CALLBACK_DATE(savedbefore, SEARCH_BEFORE, MAIL_SEARCH_DATE_TYPE_SAVED);
CALLBACK_DATE(savedon, SEARCH_ON, MAIL_SEARCH_DATE_TYPE_SAVED);
CALLBACK_DATE(savedsince, SEARCH_SINCE, MAIL_SEARCH_DATE_TYPE_SAVED);

static struct mail_search_arg *
arg_new_human_size(struct mail_search_build_context *ctx,
		   enum mail_search_arg_type type)
{
	struct mail_search_arg *sarg;
	const char *value, *error;

	sarg = mail_search_build_new(ctx, type);
	if (mail_search_parse_string(ctx->parser, &value) < 0)
		return NULL;

	if (settings_get_size(value, &sarg->value.size, &error) < 0) {
		ctx->_error = p_strdup(ctx->pool, error);
		return NULL;
	}
	return sarg;
}

static struct mail_search_arg *
human_search_larger(struct mail_search_build_context *ctx)
{ 
	return arg_new_human_size(ctx, SEARCH_LARGER);
}

static struct mail_search_arg *
human_search_smaller(struct mail_search_build_context *ctx)
{ 
	return arg_new_human_size(ctx, SEARCH_SMALLER);
}

static struct mail_search_arg *
human_search_guid(struct mail_search_build_context *ctx)
{
	return mail_search_build_str(ctx, SEARCH_GUID);
}

static struct mail_search_arg *
human_search_mailbox(struct mail_search_build_context *ctx)
{
	struct mail_search_arg *sarg;
	const char *value;

	sarg = mail_search_build_str(ctx, SEARCH_MAILBOX_GLOB);
	if (sarg == NULL)
		return NULL;

	value = sarg->value.str;

	T_BEGIN {
		string_t *str = t_str_new(128);

		if (imap_utf8_to_utf7(value, str) < 0)
			sarg->value.str = NULL;
		else
			sarg->value.str = p_strdup(ctx->pool, str_c(str));
	} T_END;
	if (sarg->value.str == NULL) {
		ctx->_error = p_strconcat(ctx->pool,
			"Mailbox name not valid UTF-8: ", value, NULL);
		return NULL;
	}
	return sarg;
}

static struct mail_search_arg *
human_search_mailbox_guid(struct mail_search_build_context *ctx)
{
	return mail_search_build_str(ctx, SEARCH_MAILBOX_GUID);
}

static const struct mail_search_register_arg human_register_args[] = {
	{ "OR", human_search_or },

	/* dates */
	{ "BEFORE", human_search_before },
	{ "ON", human_search_on },
	{ "SINCE", human_search_since },
	{ "SENTBEFORE", human_search_sentbefore },
	{ "SENTON", human_search_senton },
	{ "SENTSINCE", human_search_sentsince },
	{ "SAVEDBEFORE", human_search_savedbefore },
	{ "SAVEDON", human_search_savedon },
	{ "SAVEDSINCE", human_search_savedsince },
	{ "X-SAVEDBEFORE", human_search_savedbefore },
	{ "X-SAVEDON", human_search_savedon },
	{ "X-SAVEDSINCE", human_search_savedsince },

	/* sizes */
	{ "LARGER", human_search_larger },
	{ "SMALLER", human_search_smaller },

	/* Other Dovecot extensions: */
	{ "GUID", human_search_guid },
	{ "MAILBOX", human_search_mailbox },
	{ "MAILBOX-GUID", human_search_mailbox_guid }
};

static struct mail_search_register *
mail_search_register_init_human(struct mail_search_register *imap_register)
{
	struct mail_search_register *reg;
	mail_search_register_fallback_t *fallback;
	ARRAY_DEFINE(copy_args, const struct mail_search_register_arg);
	const struct mail_search_register_arg *human_args, *imap_args;
	unsigned int i, j, human_count, imap_count;
	int ret;

	reg = mail_search_register_init();
	mail_search_register_add(reg, human_register_args,
				 N_ELEMENTS(human_register_args));

	/* find and register args in imap that don't exist in human */
	imap_args = mail_search_register_get(imap_register, &imap_count);
	human_args = mail_search_register_get(reg, &human_count);
	t_array_init(&copy_args, imap_count);
	for (i = j = 0; i < imap_count && j < human_count; ) {
		ret = strcmp(imap_args[i].key, human_args[j].key);
		if (ret < 0) {
			array_append(&copy_args, &imap_args[i], 1);
			i++;
		} else if (ret > 0) {
			j++;
		} else {
			i++; j++;
		}
	}
	for (; i < imap_count; i++)
		array_append(&copy_args, &imap_args[i], 1);

	imap_args = array_get(&copy_args, &imap_count);
	mail_search_register_add(reg, imap_args, imap_count);

	if (mail_search_register_get_fallback(imap_register, &fallback))
		mail_search_register_fallback(reg, fallback);
	return reg;
}

struct mail_search_register *mail_search_register_get_human(void)
{
	if (mail_search_register_human == NULL) {
		struct mail_search_register *imap_reg =
			mail_search_register_get_imap();

		mail_search_register_human =
			mail_search_register_init_human(imap_reg);
	}
	return mail_search_register_human;
}
