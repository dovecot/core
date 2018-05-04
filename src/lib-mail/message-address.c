/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "strescape.h"
#include "smtp-address.h"
#include "message-parser.h"
#include "message-address.h"
#include "rfc822-parser.h"

struct message_address_parser_context {
	pool_t pool;
	struct rfc822_parser_context parser;

	struct message_address *first_addr, *last_addr, addr;
	string_t *str;

	bool fill_missing, non_strict_dots;
};

static void add_address(struct message_address_parser_context *ctx)
{
	struct message_address *addr;

	addr = p_new(ctx->pool, struct message_address, 1);

	memcpy(addr, &ctx->addr, sizeof(ctx->addr));
	i_zero(&ctx->addr);

	if (ctx->first_addr == NULL)
		ctx->first_addr = addr;
	else
		ctx->last_addr->next = addr;
	ctx->last_addr = addr;
}

/* quote with "" and escape all '\', '"' and "'" characters if need */
static void str_append_maybe_escape(string_t *dest, const char *cstr, bool escape_dot)
{
	const char *p;

	/* see if we need to quote it */
	for (p = cstr; *p != '\0'; p++) {
		if (!IS_ATEXT(*p) && (escape_dot || *p != '.'))
			break;
	}

	if (*p == '\0') {
		str_append_data(dest, cstr, (size_t) (p - cstr));
		return;
	}

	/* see if we need to escape it */
	for (p = cstr; *p != '\0'; p++) {
		if (IS_ESCAPED_CHAR(*p))
			break;
	}

	if (*p == '\0') {
		/* only quote */
		str_append_c(dest, '"');
		str_append_data(dest, cstr, (size_t) (p - cstr));
		str_append_c(dest, '"');
		return;
	}

	/* quote and escape */
	str_append_c(dest, '"');
	str_append_data(dest, cstr, (size_t) (p - cstr));

	for (; *p != '\0'; p++) {
		if (IS_ESCAPED_CHAR(*p))
			str_append_c(dest, '\\');
		str_append_c(dest, *p);
	}

	str_append_c(dest, '"');
}

static int
parse_nonstrict_dot_atom(struct rfc822_parser_context *ctx, string_t *str)
{
	int ret = -1;

	do {
		while (*ctx->data == '.') {
			str_append_c(str, '.');
			ctx->data++;
			if (ctx->data == ctx->end) {
				/* @domain is missing, but local-part
				   parsing was successful */
				return 0;
			}
			ret = 1;
		}
		if (*ctx->data == '@')
			break;
		ret = rfc822_parse_atom(ctx, str);
	} while (ret > 0 && *ctx->data == '.');
	return ret;
}

static int parse_local_part(struct message_address_parser_context *ctx)
{
	int ret;

	/*
	   local-part      = dot-atom / quoted-string / obs-local-part
	   obs-local-part  = word *("." word)
	*/
	i_assert(ctx->parser.data < ctx->parser.end);

	str_truncate(ctx->str, 0);
	if (*ctx->parser.data == '"')
		ret = rfc822_parse_quoted_string(&ctx->parser, ctx->str);
	else if (!ctx->non_strict_dots)
		ret = rfc822_parse_dot_atom(&ctx->parser, ctx->str);
	else
		ret = parse_nonstrict_dot_atom(&ctx->parser, ctx->str);
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
		if (ctx->parser.data >= ctx->parser.end)
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

static int parse_angle_addr(struct message_address_parser_context *ctx,
			    bool parsing_path)
{
	/* "<" [ "@" route ":" ] local-part "@" domain ">" */
	i_assert(*ctx->parser.data == '<');
	ctx->parser.data++;

	if (rfc822_skip_lwsp(&ctx->parser) <= 0)
		return -1;

	if (*ctx->parser.data == '@') {
		if (parse_domain_list(ctx) > 0 && *ctx->parser.data == ':') {
			ctx->parser.data++;
		} else if (parsing_path && *ctx->parser.data != ':') {
			return -1;
		} else {
			if (ctx->fill_missing)
				ctx->addr.route = "INVALID_ROUTE";
			if (ctx->parser.data >= ctx->parser.end)
				return -1;
			/* try to continue anyway */
		}
		if (rfc822_skip_lwsp(&ctx->parser) <= 0)
			return -1;
	}

	if (*ctx->parser.data == '>') {
		/* <> address isn't valid */
	} else {
		if (parse_local_part(ctx) <= 0)
			return -1;
		if (*ctx->parser.data == '@') {
			if (parse_domain(ctx) <= 0)
				return -1;
		}
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
	if (parse_angle_addr(ctx, FALSE) < 0) {
		/* broken */
		if (ctx->fill_missing)
			ctx->addr.domain = "SYNTAX_ERROR";
		ctx->addr.invalid_syntax = TRUE;
	}
	return ctx->parser.data < ctx->parser.end ? 1 : 0;
}

static int parse_addr_spec(struct message_address_parser_context *ctx)
{
	/* addr-spec       = local-part "@" domain */
	int ret, ret2 = -2;

	i_assert(ctx->parser.data < ctx->parser.end);

	str_truncate(ctx->parser.last_comment, 0);

	bool quoted_string = *ctx->parser.data == '"';
	ret = parse_local_part(ctx);
	if (ret <= 0) {
		/* end of input or parsing local-part failed */
		ctx->addr.invalid_syntax = TRUE;
	}
	if (ret != 0 && ctx->parser.data < ctx->parser.end &&
	    *ctx->parser.data == '@') {
		ret2 = parse_domain(ctx);
		if (ret2 <= 0)
			ret = ret2;
	}

	if (str_len(ctx->parser.last_comment) > 0)
		ctx->addr.name = p_strdup(ctx->pool, str_c(ctx->parser.last_comment));
	else if (ret2 == -2) {
		/* So far we've read user without @domain and without
		   (Display Name). We'll assume that a single "user" (already
		   read into addr.mailbox) is a mailbox, but if it's followed
		   by anything else it's a display-name. */
		str_append_c(ctx->str, ' ');
		size_t orig_str_len = str_len(ctx->str);
		(void)rfc822_parse_phrase(&ctx->parser, ctx->str);
		if (str_len(ctx->str) != orig_str_len) {
			ctx->addr.mailbox = NULL;
			ctx->addr.name = p_strdup(ctx->pool, str_c(ctx->str));
		} else {
			if (!quoted_string)
				ctx->addr.domain = "";
		}
		ctx->addr.invalid_syntax = TRUE;
		ret = -1;
	}
	return ret;
}

static void add_fixed_address(struct message_address_parser_context *ctx)
{
	if (ctx->addr.mailbox == NULL) {
		ctx->addr.mailbox = !ctx->fill_missing ? "" : "MISSING_MAILBOX";
		ctx->addr.invalid_syntax = TRUE;
	}
	if (ctx->addr.domain == NULL || ctx->addr.domain[0] == '\0') {
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
		if (ctx->addr.invalid_syntax && ctx->addr.name == NULL &&
		    ctx->addr.mailbox != NULL && ctx->addr.domain == NULL) {
			ctx->addr.name = ctx->addr.mailbox;
			ctx->addr.mailbox = NULL;
		}
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
				/* broken mailbox - try to continue anyway. */
			}
			if (ctx->parser.data >= ctx->parser.end ||
			    *ctx->parser.data != ',')
				break;
			ctx->parser.data++;
			if (rfc822_skip_lwsp(&ctx->parser) <= 0) {
				ret = -1;
				break;
			}
		}
	}
	if (ret >= 0) {
		if (ctx->parser.data >= ctx->parser.end ||
		    *ctx->parser.data != ';')
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
	while (max_addresses > 0) {
		max_addresses--;
		if ((ret = parse_address(ctx)) == 0)
			break;
		if (ctx->parser.data >= ctx->parser.end ||
		    *ctx->parser.data != ',') {
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

static int parse_path(struct message_address_parser_context *ctx)
{
	int ret;

	if (rfc822_skip_lwsp(&ctx->parser) <= 0)
		return -1;
	if (*ctx->parser.data != '<') {
		/* Cope with paths that omit < and >. This is a syntax
		   violation, but we allow it to account for a rather wide
		   selection of software that does not follow the standards.
		 */
		if ((ret=parse_local_part(ctx)) > 0 &&
		    *ctx->parser.data == '@') {
			ret = parse_domain(ctx);
		}
	} else {
		ret = parse_angle_addr(ctx, TRUE);
	}
	if (ret < 0 || (ret=rfc822_skip_lwsp(&ctx->parser)) < 0 ||
	    ctx->parser.data != ctx->parser.end ||
	    (ctx->addr.mailbox != NULL &&
	     (ctx->addr.domain == NULL || *ctx->addr.domain == '\0')) ||
	    (ctx->addr.mailbox == NULL && ctx->addr.domain != NULL)) {
		ctx->addr.invalid_syntax = TRUE;
		ret = -1;
	}
	add_address(ctx);
	return ret;
}

static struct message_address *
message_address_parse_real(pool_t pool, const unsigned char *data, size_t size,
			   unsigned int max_addresses,
			   enum message_address_parse_flags flags)
{
	struct message_address_parser_context ctx;

	i_zero(&ctx);

	rfc822_parser_init(&ctx.parser, data, size, t_str_new(128));
	ctx.parser.nul_replacement_str = RFC822_NUL_REPLACEMENT_STR;
	ctx.pool = pool;
	ctx.str = t_str_new(128);
	ctx.fill_missing = (flags & MESSAGE_ADDRESS_PARSE_FLAG_FILL_MISSING) != 0;
	ctx.non_strict_dots = (flags & MESSAGE_ADDRESS_PARSE_FLAG_NON_STRICT_DOTS) != 0;

	if (rfc822_skip_lwsp(&ctx.parser) <= 0) {
		/* no addresses */
	} else {
		(void)parse_address_list(&ctx, max_addresses);
	}
	rfc822_parser_deinit(&ctx.parser);
	return ctx.first_addr;
}

static int
message_address_parse_path_real(pool_t pool, const unsigned char *data,
				size_t size, struct message_address **addr_r)
{
	struct message_address_parser_context ctx;
	int ret;

	i_zero(&ctx);
	*addr_r = NULL;

	rfc822_parser_init(&ctx.parser, data, size, NULL);
	ctx.pool = pool;
	ctx.str = t_str_new(128);

	ret = parse_path(&ctx);

	rfc822_parser_deinit(&ctx.parser);
	*addr_r = ctx.first_addr;
	return (ret < 0 ? -1 : 0);
}

struct message_address *
message_address_parse(pool_t pool, const unsigned char *data, size_t size,
		      unsigned int max_addresses,
		      enum message_address_parse_flags flags)
{
	struct message_address *addr;

	if (pool->datastack_pool) {
		return message_address_parse_real(pool, data, size,
						  max_addresses, flags);
	}
	T_BEGIN {
		addr = message_address_parse_real(pool, data, size,
						  max_addresses, flags);
	} T_END;
	return addr;
}

int message_address_parse_path(pool_t pool, const unsigned char *data,
			       size_t size, struct message_address **addr_r)
{
	int ret;

	if (pool->datastack_pool) {
		return message_address_parse_path_real(pool, data, size, addr_r);
	}
	T_BEGIN {
		ret = message_address_parse_path_real(pool, data, size, addr_r);
	} T_END;
	return ret;
}

void message_address_write(string_t *str, const struct message_address *addr)
{
	const char *tmp;
	bool first = TRUE, in_group = FALSE;

	if (addr == NULL)
		return;

	/* <> path */
	if (addr->mailbox == NULL && addr->domain == NULL) {
		i_assert(addr->next == NULL);
		str_append(str, "<>");
		return;
	}

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
				if (addr->mailbox != NULL && *addr->mailbox != '\0') {
					/* check for MIME encoded-word */
					if (strstr(addr->mailbox, "=?") != NULL)
						/* MIME encoded-word MUST NOT appear within a 'quoted-string'
						   so escaping and quoting of phrase is not possible, instead
						   use obsolete RFC822 phrase syntax which allow spaces */
						str_append(str, addr->mailbox);
					else
						str_append_maybe_escape(str, addr->mailbox, TRUE);
				} else {
					/* empty group name needs to be quoted */
					str_append(str, "\"\"");
				}
				str_append(str, ": ");
				first = TRUE;
			} else {
				/* end of group. all fields should be NULL. */
				i_assert(addr->mailbox == NULL);

				/* cut out the ", " */
				tmp = str_c(str)+str_len(str)-2;
				i_assert((tmp[0] == ',' || tmp[0] == ':') && tmp[1] == ' ');
				if (tmp[0] == ',' && tmp[1] == ' ')
					str_truncate(str, str_len(str)-2);
				else if (tmp[0] == ':' && tmp[1] == ' ')
					str_truncate(str, str_len(str)-1);
				str_append_c(str, ';');
			}

			in_group = !in_group;
		} else {
			/* "Display Name" <mailbox@domain> */
			i_assert(addr->mailbox != NULL);

			if (addr->name != NULL) {
				/* check for MIME encoded-word */
				if (strstr(addr->name, "=?") != NULL)
					/* MIME encoded-word MUST NOT appear within a 'quoted-string'
					   so escaping and quoting of phrase is not possible, instead
					   use obsolete RFC822 phrase syntax which allow spaces */
					str_append(str, addr->name);
				else
					str_append_maybe_escape(str, addr->name, TRUE);
			}
			if (addr->route != NULL ||
			    addr->mailbox[0] != '\0' ||
			    addr->domain[0] != '\0') {
				if (addr->name != NULL && addr->name[0] != '\0')
					str_append_c(str, ' ');
				str_append_c(str, '<');
				if (addr->route != NULL) {
					str_append(str, addr->route);
					str_append_c(str, ':');
				}
				if (addr->mailbox[0] == '\0')
					str_append(str, "\"\"");
				else
					str_append_maybe_escape(str, addr->mailbox, FALSE);
				if (addr->domain[0] != '\0') {
					str_append_c(str, '@');
					str_append(str, addr->domain);
				}
				str_append_c(str, '>');
			}
		}

		addr = addr->next;
	}
}

const char *message_address_to_string(const struct message_address *addr)
{
	string_t *str = t_str_new(256);
	message_address_write(str, addr);
	return str_c(str);
}

const char *message_address_first_to_string(const struct message_address *addr)
{
	struct message_address first_addr;

	first_addr = *addr;
	first_addr.next = NULL;
	first_addr.route = NULL;
	return message_address_to_string(&first_addr);
}

void message_address_init(struct message_address *addr,
	const char *name, const char *mailbox, const char *domain)
{
	i_zero(addr);
	addr->name = name;
	addr->mailbox = mailbox;
	addr->domain = domain;
}

void message_address_init_from_smtp(struct message_address *addr,
	const char *name, const struct smtp_address *smtp_addr)
{
	i_zero(addr);
	addr->name = name;
	addr->mailbox = smtp_addr->localpart;
	addr->domain = smtp_addr->domain;
}

static const char *address_headers[] = {
	"From", "Sender", "Reply-To",
	"To", "Cc", "Bcc",
	"Resent-From", "Resent-Sender", "Resent-To", "Resent-Cc", "Resent-Bcc"
};

bool message_header_is_address(const char *hdr_name)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(address_headers); i++) {
		if (strcasecmp(hdr_name, address_headers[i]) == 0)
			return TRUE;
	}
	return FALSE;
}
