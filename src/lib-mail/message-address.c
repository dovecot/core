/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "message-parser.h"
#include "message-address.h"
#include "rfc822-parser.h"

struct message_address_parser_context {
	pool_t pool;
	struct rfc822_parser_context parser;

	struct message_address *first_addr, *last_addr, addr;
	string_t *str;

	bool fill_missing;
};

static void add_address(struct message_address_parser_context *ctx)
{
	struct message_address *addr;

	addr = p_new(ctx->pool, struct message_address, 1);

	memcpy(addr, &ctx->addr, sizeof(ctx->addr));
	memset(&ctx->addr, 0, sizeof(ctx->addr));

	if (ctx->first_addr == NULL)
		ctx->first_addr = addr;
	else
		ctx->last_addr->next = addr;
	ctx->last_addr = addr;
}

static int parse_local_part(struct message_address_parser_context *ctx)
{
	int ret;

	/*
	   local-part      = dot-atom / quoted-string / obs-local-part
	   obs-local-part  = word *("." word)
	*/
	i_assert(ctx->parser.data != ctx->parser.end);

	str_truncate(ctx->str, 0);
	if (*ctx->parser.data == '"')
		ret = rfc822_parse_quoted_string(&ctx->parser, ctx->str);
	else
		ret = rfc822_parse_dot_atom(&ctx->parser, ctx->str);
	if (ret < 0)
		return -1;

	ctx->addr.mailbox = p_strdup(ctx->pool, str_c(ctx->str));
	return ret;
}

static int parse_domain(struct message_address_parser_context *ctx)
{
	int ret;

	str_truncate(ctx->str, 0);
	if ((ret = rfc822_parse_domain(&ctx->parser, ctx->str)) < 0)
		return -1;

	ctx->addr.domain = p_strdup(ctx->pool, str_c(ctx->str));
	return ret;
}

static int parse_domain_list(struct message_address_parser_context *ctx)
{
	int ret;

	/* obs-domain-list = "@" domain *(*(CFWS / "," ) [CFWS] "@" domain) */
	str_truncate(ctx->str, 0);
	for (;;) {
		if (ctx->parser.data == ctx->parser.end)
			return 0;

		if (*ctx->parser.data != '@')
			break;

		if (str_len(ctx->str) > 0)
			str_append_c(ctx->str, ',');

		str_append_c(ctx->str, '@');
		if ((ret = rfc822_parse_domain(&ctx->parser, ctx->str)) <= 0)
			return ret;

		while (rfc822_skip_lwsp(&ctx->parser) > 0 &&
		       *ctx->parser.data == ',')
			ctx->parser.data++;
	}
	ctx->addr.route = p_strdup(ctx->pool, str_c(ctx->str));
	return 1;
}

static int parse_angle_addr(struct message_address_parser_context *ctx)
{
	int ret;

	/* "<" [ "@" route ":" ] local-part "@" domain ">" */
	i_assert(*ctx->parser.data == '<');
	ctx->parser.data++;

	if ((ret = rfc822_skip_lwsp(&ctx->parser)) <= 0)
		return ret;

	if (*ctx->parser.data == '@') {
		if (parse_domain_list(ctx) <= 0 || *ctx->parser.data != ':') {
			ctx->addr.route = "INVALID_ROUTE";
			return -1;
		}
		ctx->parser.data++;
		if ((ret = rfc822_skip_lwsp(&ctx->parser)) <= 0)
			return ret;
	}

	if ((ret = parse_local_part(ctx)) <= 0)
		return ret;
	if (*ctx->parser.data == '@') {
		if ((ret = parse_domain(ctx)) <= 0)
			return ret;
	}

	if (*ctx->parser.data != '>')
		return -1;
	ctx->parser.data++;

	return rfc822_skip_lwsp(&ctx->parser);
}

static int parse_name_addr(struct message_address_parser_context *ctx)
{
	/*
	   name-addr       = [display-name] angle-addr
	   display-name    = phrase
	*/
	str_truncate(ctx->str, 0);
	if (rfc822_parse_phrase(&ctx->parser, ctx->str) <= 0 ||
	    *ctx->parser.data != '<')
		return -1;

	ctx->addr.name = p_strdup(ctx->pool, str_c(ctx->str));
	if (*ctx->addr.name == '\0') {
		/* Cope with "<address>" without display name */
		ctx->addr.name = NULL;
	}
	if (parse_angle_addr(ctx) < 0) {
		/* broken */
		ctx->addr.domain = "SYNTAX_ERROR";
		ctx->addr.invalid_syntax = TRUE;
	}
	return ctx->parser.data != ctx->parser.end;
}

static int parse_addr_spec(struct message_address_parser_context *ctx)
{
	/* addr-spec       = local-part "@" domain */
	int ret, ret2;

	str_truncate(ctx->parser.last_comment, 0);

	ret = parse_local_part(ctx);
	if (ret != 0 && *ctx->parser.data == '@') {
		ret2 = parse_domain(ctx);
		if (ret2 <= 0)
			ret = ret2;
	}

	if (str_len(ctx->parser.last_comment) > 0) {
		ctx->addr.name =
			p_strdup(ctx->pool, str_c(ctx->parser.last_comment));
	}
	return ret;
}

static void add_fixed_address(struct message_address_parser_context *ctx)
{
	if (ctx->addr.mailbox == NULL) {
		ctx->addr.mailbox = !ctx->fill_missing ? "" : "MISSING_MAILBOX";
		ctx->addr.invalid_syntax = TRUE;
	}
	if (ctx->addr.domain == NULL) {
		ctx->addr.domain = !ctx->fill_missing ? "" : "MISSING_DOMAIN";
		ctx->addr.invalid_syntax = TRUE;
	}
	add_address(ctx);
}

static int parse_mailbox(struct message_address_parser_context *ctx)
{
	const unsigned char *start;
	int ret;

	/* mailbox         = name-addr / addr-spec */
	start = ctx->parser.data;
	if ((ret = parse_name_addr(ctx)) < 0) {
		/* nope, should be addr-spec */
		ctx->parser.data = start;
		ret = parse_addr_spec(ctx);
	}

	if (ret < 0)
		ctx->addr.invalid_syntax = TRUE;
	add_fixed_address(ctx);
	return ret;
}

static int parse_group(struct message_address_parser_context *ctx)
{
	int ret;

	/*
	   group           = display-name ":" [mailbox-list / CFWS] ";" [CFWS]
	   display-name    = phrase
	*/
	str_truncate(ctx->str, 0);
	if (rfc822_parse_phrase(&ctx->parser, ctx->str) <= 0 ||
	    *ctx->parser.data != ':')
		return -1;

	/* from now on don't return -1 even if there are problems, so that
	   the caller knows this is a group */
	ctx->parser.data++;
	if ((ret = rfc822_skip_lwsp(&ctx->parser)) <= 0)
		ctx->addr.invalid_syntax = TRUE;

	ctx->addr.mailbox = p_strdup(ctx->pool, str_c(ctx->str));
	add_address(ctx);

	if (ret > 0 && *ctx->parser.data != ';') {
		for (;;) {
			/* mailbox-list    =
			   	(mailbox *("," mailbox)) / obs-mbox-list */
			if (parse_mailbox(ctx) <= 0) {
				ret = -1;
				break;
			}
			if (*ctx->parser.data != ',')
				break;
			ctx->parser.data++;
			if (rfc822_skip_lwsp(&ctx->parser) <= 0) {
				ret = -1;
				break;
			}
		}
	}
	if (ret >= 0) {
		if (*ctx->parser.data != ';')
			ret = -1;
		else {
			ctx->parser.data++;
			ret = rfc822_skip_lwsp(&ctx->parser);
		}
	}
	if (ret < 0)
		ctx->addr.invalid_syntax = TRUE;

	add_address(ctx);
	return ret == 0 ? 0 : 1;
}

static int parse_address(struct message_address_parser_context *ctx)
{
	const unsigned char *start;
	int ret;

	/* address         = mailbox / group */
	start = ctx->parser.data;
	if ((ret = parse_group(ctx)) < 0) {
		/* not a group, try mailbox */
		ctx->parser.data = start;
		ret = parse_mailbox(ctx);
	}
	return ret;
}

static int parse_address_list(struct message_address_parser_context *ctx,
			      unsigned int max_addresses)
{
	int ret = 0;

	/* address-list    = (address *("," address)) / obs-addr-list */
	while (max_addresses-- > 0) {
		if ((ret = parse_address(ctx)) == 0)
			break;
		if (*ctx->parser.data != ',') {
			ret = -1;
			break;
		}
		ctx->parser.data++;
		if ((ret = rfc822_skip_lwsp(&ctx->parser)) <= 0) {
			if (ret < 0) {
				/* ends with some garbage */
				add_fixed_address(ctx);
			}
			break;
		}
	}
	return ret;
}

static struct message_address *
message_address_parse_real(pool_t pool, const unsigned char *data, size_t size,
			   unsigned int max_addresses, bool fill_missing)
{
	struct message_address_parser_context ctx;

	memset(&ctx, 0, sizeof(ctx));

	rfc822_parser_init(&ctx.parser, data, size, t_str_new(128));
	ctx.pool = pool;
	ctx.str = t_str_new(128);
	ctx.fill_missing = fill_missing;

	if (rfc822_skip_lwsp(&ctx.parser) <= 0) {
		/* no addresses */
		return NULL;
	}
	(void)parse_address_list(&ctx, max_addresses);
	return ctx.first_addr;
}

struct message_address *
message_address_parse(pool_t pool, const unsigned char *data, size_t size,
		      unsigned int max_addresses, bool fill_missing)
{
	struct message_address *addr;

	if (pool->datastack_pool) {
		return message_address_parse_real(pool, data, size,
						  max_addresses, fill_missing);
	}
	T_BEGIN {
		addr = message_address_parse_real(pool, data, size,
						  max_addresses, fill_missing);
	} T_END;
	return addr;
}

void message_address_write(string_t *str, const struct message_address *addr)
{
	bool first = TRUE, in_group = FALSE;

	/* a) mailbox@domain
	   b) name <@route:mailbox@domain>
	   c) group: .. ; */

	while (addr != NULL) {
		if (first)
			first = FALSE;
		else
			str_append(str, ", ");

		if (addr->domain == NULL) {
			if (!in_group) {
				/* beginning of group. mailbox is the group
				   name, others are NULL. */
				if (addr->mailbox != NULL)
					str_append(str, addr->mailbox);
				str_append(str, ": ");
				first = TRUE;
			} else {
				/* end of group. all fields should be NULL. */
				i_assert(addr->mailbox == NULL);

				/* cut out the ", " */
				str_truncate(str, str_len(str)-2);
				str_append_c(str, ';');
			}

			in_group = !in_group;
		} else if ((addr->name == NULL || *addr->name == '\0') &&
			   addr->route == NULL) {
			/* no name and no route. use only mailbox@domain */
			i_assert(addr->mailbox != NULL);

			str_append(str, addr->mailbox);
			str_append_c(str, '@');
			str_append(str, addr->domain);
		} else {
			/* name and/or route. use full <mailbox@domain> Name */
			i_assert(addr->mailbox != NULL);

			if (addr->name != NULL) {
				str_append(str, addr->name);
				str_append_c(str, ' ');
			}
			str_append_c(str, '<');
			if (addr->route != NULL) {
				str_append(str, addr->route);
				str_append_c(str, ':');
			}
			str_append(str, addr->mailbox);
			str_append_c(str, '@');
			str_append(str, addr->domain);
			str_append_c(str, '>');
		}

		addr = addr->next;
	}
}
