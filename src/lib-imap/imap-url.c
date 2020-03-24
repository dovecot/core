/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "strfuncs.h"
#include "str-sanitize.h"
#include "hex-binary.h"
#include "net.h"
#include "iso8601-date.h"
#include "uri-util.h"

#include "imap-url.h"

#include <ctype.h>

/*
 * IMAP URL parsing
 */

/*
IMAP URL Grammar overview

RFC5092 Section 11:

imapurl          = "imap://" iserver ipath-query
                   ; Defines an absolute IMAP URL
iserver          = [iuserinfo "@"] host [ ":" port ]
                   ; This is the same as "authority" defined in [URI-GEN].
iuserinfo        = enc-user [iauth] / [enc-user] iauth
                   ; conforms to the generic syntax of "userinfo" as
                   ; defined in [URI-GEN].
enc-user         = 1*achar
                   ; %-encoded version of [IMAP4] authorization identity or
                   ; "userid".
iauth            = ";AUTH=" ( "*" / enc-auth-type )
enc-auth-type    = 1*achar
                   ; %-encoded version of [IMAP4] "auth-type"
ipath-query      = ["/" [ icommand ]]
                   ; Corresponds to "path-abempty [ "?" query ]" in
                   ; [URI-GEN]
icommand         = imessagelist /
                   imessagepart [iurlauth]
imessagelist     = imailbox-ref [ "?" enc-search ]
                   ; "enc-search" is [URI-GEN] "query".
imessagepart     = imailbox-ref iuid [isection] [ipartial]
imailbox-ref     = enc-mailbox [uidvalidity]
uidvalidity      = ";UIDVALIDITY=" nz-number
                   ; See [IMAP4] for "nz-number" definition
iuid             = "/" iuid-only
iuid-only        = ";UID=" nz-number
                   ; See [IMAP4] for "nz-number" definition
isection         = "/" isection-only
isection-only    = ";SECTION=" enc-section
ipartial         = "/" ipartial-only
ipartial-only    = ";PARTIAL=" partial-range
enc-search       = 1*bchar
                   ; %-encoded version of [IMAPABNF]
                   ; "search-program".  Note that IMAP4
                   ; literals may not be used in
                   ; a "search-program", i.e., only
                   ; quoted or non-synchronizing
                   ; literals (if the server supports
                   ; LITERAL+ [LITERAL+]) are allowed.
enc-mailbox      = 1*bchar
                   ; %-encoded version of [IMAP4] "mailbox"
enc-section      = 1*bchar
                   ; %-encoded version of [IMAP4] "section-spec"
partial-range    = number ["." nz-number]
                   ; partial FETCH.  The first number is
                   ; the offset of the first byte,
                   ; the second number is the length of
                   ; the fragment.
bchar            = achar / ":" / "@" / "/"
achar            = uchar / "&" / "="
                   ;; Same as [URI-GEN] 'unreserved / sub-delims /
                   ;; pct-encoded', but ";" is disallowed.
uchar            = unreserved / sub-delims-sh / pct-encoded
sub-delims-sh    = "!" / "$" / "'" / "(" / ")" /
                   "*" / "+" / ","
                   ;; Same as [URI-GEN] sub-delims,
                   ;; but without ";", "&" and "=".

The following rules are only used in the presence of the IMAP
[URLAUTH] extension:

authimapurl      = "imap://" iserver "/" imessagepart
                   ; Same as "imapurl" when "[icommand]" is
                   ; "imessagepart"
authimapurlfull  = authimapurl iurlauth
                   ; Same as "imapurl" when "[icommand]" is
                   ; "imessagepart iurlauth"
authimapurlrump  = authimapurl iurlauth-rump

iurlauth         = iurlauth-rump iua-verifier
enc-urlauth      = 32*HEXDIG
iua-verifier     = ":" uauth-mechanism ":" enc-urlauth
iurlauth-rump    = [expire] ";URLAUTH=" access
access           = ("submit+" enc-user) / ("user+" enc-user) /
                   "authuser" / "anonymous"
expire           = ";EXPIRE=" date-time
                   ; date-time is defined in [DATETIME]
uauth-mechanism  = "INTERNAL" / 1*(ALPHA / DIGIT / "-" / ".")
                   ; Case-insensitive.

[URI-GEN] RFC3986 Appendix A:

Implemented in src/lib/uri-util.c

*/

/*
 * Imap URL parser
 */

struct imap_url_parser {
	struct uri_parser parser;

	enum imap_url_parse_flags flags;

	struct imap_url *url;
	const struct imap_url *base;

	bool relative:1;
};

static int
imap_url_parse_number(struct uri_parser *parser, const char *data,
		      uint32_t *number_r)
{
	/* [IMAP4] RFC3501, Section 9
	 *
	 * number          = 1*DIGIT
	 *                   ; Unsigned 32-bit integer
	 *                   ; (0 <= n < 4,294,967,296)
	 */

	if (i_isdigit(*data)) {
		if (str_to_uint32(data, number_r) == 0)
			return 1;
		parser->error = "IMAP number is too high";
		return -1;
	}

	parser->error = t_strdup_printf(
		"Value '%s' is not a valid IMAP number", data);
	return -1;
}

static int
imap_url_parse_offset(struct uri_parser *parser, const char *data,
		      uoff_t *number_r)
{
	/* Syntax for big (uoff_t) numbers. Not strictly IMAP syntax, but this
	   is handled similarly for Dovecot IMAP FETCH BODY partial <.>
	   implementation. */
	if (i_isdigit(*data)) {
		if (str_to_uoff(data, number_r) == 0)
			return 1;
		parser->error = "IMAP number is too high";
		return -1;
	}

	parser->error = t_strdup_printf(
		"Value '%s' is not a valid IMAP number", data);
	return -1;
}

static int imap_url_parse_iserver(struct imap_url_parser *url_parser)
{
	struct uri_parser *parser = &url_parser->parser;
	struct uri_authority auth;
	struct imap_url *url = url_parser->url;
	const char *data;
	int ret = 0;

	/* imapurl          = "imap://" iserver {...}
	 * inetwork-path    = "//" iserver {...}
	 * iserver          = [iuserinfo "@"] host [":" port]
	 *                    ; This is the same as "authority" defined
	 *                    ; in [URI-GEN].
	 * iuserinfo        = enc-user [iauth] / [enc-user] iauth
	 *                    ; conforms to the generic syntax of "userinfo" as
	 *                    ; defined in [URI-GEN].
	 * enc-user         = 1*achar
	 *                    ; %-encoded version of [IMAP4] authorization identity or
	 *                    ; "userid".
	 * iauth            = ";AUTH=" ( "*" / enc-auth-type )
	 * enc-auth-type    = 1*achar
	 *                    ; %-encoded version of [IMAP4] "auth-type"
	 */

	/* "//" iserver */
	if ((ret = uri_parse_slashslash_host_authority
		(parser, &auth)) <= 0)
		return ret;
	if (auth.host.name == NULL || *auth.host.name == '\0') {
		/* This situation is not documented anywhere, but it is not
		   currently useful either and potentially problematic if not
		   handled explicitly everywhere. So, it is denied hier for now.
		 */
		parser->error = "IMAP URL does not allow empty host identifier";
		return -1;
	}
	/* iuserinfo        = enc-user [iauth] / [enc-user] iauth */
	if (auth.enc_userinfo != NULL) {
		const char *p, *uend;

		/* Scan for ";AUTH=" */
		for (p = auth.enc_userinfo; *p != '\0'; p++) {
			if (*p == ';')
				break;
			/* check for unallowed userinfo characters */
			if (*p == ':') {
				parser->error = t_strdup_printf(
					"Stray ':' in userinfo `%s'", auth.enc_userinfo);
				return -1;
			}
		}

		uend = p;

		if (*p == ';') {
			if (strncasecmp(p, ";AUTH=", 6) != 0) {
				parser->error = t_strdup_printf(
					"Stray ';' in userinfo `%s'",
					auth.enc_userinfo);
				return -1;
			}

			for (p += 6; *p != '\0'; p++) {
				if (*p == ';' || *p == ':') {
					parser->error = t_strdup_printf(
						"Stray '%c' in userinfo `%s'", *p, auth.enc_userinfo);
					return -1;
				}
			}
		}

		/* enc-user */
		if (url != NULL && uend > auth.enc_userinfo) {
			if (!uri_data_decode(parser, auth.enc_userinfo, uend, &data))
				return -1;
			url->userid = p_strdup(parser->pool, data);
		}

		/* ( "*" / enc-auth-type ) */
		if (*uend == ';') {
			p = uend + 6;
			if (*p == '\0') {
				parser->error = "Empty auth-type value after ';AUTH='";
				return -1;
			}
			if (url != NULL) {
				if (!uri_data_decode(parser, p, NULL, &data))
					return -1;
				url->auth_type = p_strdup(parser->pool, data);
			}
		}
	}

	if (url != NULL) {
		url->host = auth.host;
		url->port = auth.port;
	}
	return 1;
}

static int
imap_url_parse_urlauth(struct imap_url_parser *url_parser, const char *urlext)
{
	struct uri_parser *parser = &url_parser->parser;
	struct imap_url *url = url_parser->url;
	const char *p, *q, *data;
	buffer_t *uauth_token;
	time_t expire = (time_t)-1;
	int tz;

	/* iurlauth         = iurlauth-rump iua-verifier
	 * enc-urlauth      = 32*HEXDIG
	 * iua-verifier     = ":" uauth-mechanism ":" enc-urlauth
	 * iurlauth-rump    = [expire] ";URLAUTH=" access
	 * access           = ("submit+" enc-user) / ("user+" enc-user) /
	 *                    "authuser" / "anonymous"
	 * expire           = ";EXPIRE=" date-time
	 *                    ; date-time is defined in [DATETIME]
	 * uauth-mechanism  = "INTERNAL" / 1*(ALPHA / DIGIT / "-" / ".")
	 *                    ; Case-insensitive.
	 */

	/* ";EXPIRE=" date-time */
	if (strncasecmp(urlext, ";EXPIRE=", 8) == 0) {
		if ((url_parser->flags & IMAP_URL_PARSE_ALLOW_URLAUTH) == 0) {
			parser->error = "`;EXPIRE=' is not allowed in this context";
			return -1;
		}

		if ((p = strchr(urlext+8, ';')) != NULL) {
			if (!iso8601_date_parse((const unsigned char *)urlext+8,
						p-urlext-8, &expire, &tz)) {
				parser->error = "invalid date-time for `;EXPIRE='";
				return -1;
			}
			urlext = p;
		}
	}

	/* ";URLAUTH=" access */
	if (strncasecmp(urlext, ";URLAUTH=", 9) != 0) {
		if (expire != (time_t)-1) {
			parser->error = "`;EXPIRE=' without `;URLAUTH='";
			return -1;
		}
		return 0;
	}
	urlext += 9;

	if (url != NULL)
		url->uauth_expire = expire;

	if ((url_parser->flags & IMAP_URL_PARSE_ALLOW_URLAUTH) == 0) {
		parser->error = "`;URLAUTH=' is not allowed in this context";
		return -1;
	}

	if (url_parser->relative) {
		parser->error = "IMAP URLAUTH requires absolute URL";
		return -1;
	}

	if ((p = strchr(urlext, ':')) == NULL) {
		size_t len = strlen(urlext);
		if (len == 0) {
			parser->error = "Missing URLAUTH access specifier";
			return -1;
		}	
		p = urlext+len;
	} else if (p == urlext) {
		parser->error = "Empty URLAUTH access specifier";
		return -1;	
	}

	/* parse access */
	if ((q = strchr(urlext, '+')) == NULL) {
		/* application */
		if (url != NULL) {
			url->uauth_access_application =
				p_strdup_until(parser->pool, urlext, p);
		}
	} else {
		/* application "+" enc-user */
		if (urlext == q) {
			parser->error = "Empty URLAUTH access application";
			return -1;
		}
		if (q+1 == p) {
			parser->error = t_strdup_printf(
				"Empty URLAUTH access user for `%s' application",
				t_strdup_until(urlext, q));
			return -1;
		}
		if (!uri_data_decode(parser, q+1, p, &data))
			return -1;
		if (url != NULL) {
			url->uauth_access_application =
				p_strdup_until(parser->pool, urlext, q);
			url->uauth_access_user = p_strdup(parser->pool, data);
		}
	}

	if (url != NULL) {
		/* get rump url */
		if ((url_parser->flags & IMAP_URL_PARSE_SCHEME_EXTERNAL) == 0) {
			url->uauth_rumpurl = p_strdup_until(parser->pool,
				parser->begin, parser->end-strlen(p));
		} else {
			url->uauth_rumpurl = p_strconcat(parser->pool, "imap:",
				t_strdup_until(parser->begin, parser->end-strlen(p)),
				NULL);
		}
	}

	if (*p == '\0') {
		/* rump url; caller should check whether this is appropriate */
		return 1;
	}

	/* iua-verifier     = ":" uauth-mechanism ":" enc-urlauth */

	q = p + 1;
	if (*q == '\0') {
		parser->error = "Missing URLAUTH verifier";
		return -1;
	}
	if ((p = strchr(q, ':')) == NULL || p[1] == '\0') {
		parser->error = "Missing URLAUTH token";
		return -1;
	}
	if (p == q) {
		parser->error = "Missing URLAUTH mechanism";
		return -1;
	}
	if (url != NULL) {
		/* get mechanism */
		url->uauth_mechanism = p_strdup_until(parser->pool, q, p);
	}

	/* enc-urlauth      = 32*HEXDIG */

	q = p+1;
	if (strlen(q) < 32) {
		parser->error = "Too short URLAUTH token";
		return -1;
	}

	uauth_token = t_buffer_create(64);
	if (hex_to_binary(q, uauth_token) < 0) {
		parser->error = "Invalid URLAUTH token";
		return -1;
	}

	if (url != NULL) {
		url->uauth_token = uauth_token->data;
		url->uauth_token_size = uauth_token->used;
	}
	return 1;
}

static int
imap_url_parse_path(struct imap_url_parser *url_parser,
		    const char *const *path, int relative,
		    bool *is_messagelist_r)
{
	struct uri_parser *parser = &url_parser->parser;
	struct imap_url *url = url_parser->url;
	const char *const *segment;
	string_t *mailbox, *section = NULL;
	uint32_t uid = 0, uidvalidity = 0;
	uoff_t partial_offset = 0, partial_size = 0;
	bool have_partial = FALSE;
	const char *p, *value, *urlext = NULL;
	bool mailbox_endslash = FALSE, section_endslash = FALSE;
	int ret;

	/* icommand         = imessagelist /
	 *                    imessagepart [iurlauth]
	 * imessagelist     = imailbox-ref [ "?" enc-search ]
	 *                    ; "enc-search" is [URI-GEN] "query".
	 * imessagepart     = imailbox-ref iuid [isection] [ipartial]
	 * imailbox-ref     = enc-mailbox [uidvalidity]
	 * uidvalidity      = ";UIDVALIDITY=" nz-number
	 * iuid             = "/" iuid-only
	 * iuid-only        = ";UID=" nz-number
	 *                    ; See [IMAP4] for "nz-number" definition
	 * isection         = "/" isection-only
	 * isection-only    = ";SECTION=" enc-section
	 * ipartial         = "/" ipartial-only
	 * ipartial-only    = ";PARTIAL=" partial-range
	 * enc-mailbox      = 1*bchar
	 *                    ; %-encoded version of [IMAP4] "mailbox"
	 * enc-section      = 1*bchar
	 *                    ; %-encoded version of [IMAP4] "section-spec"
	 * partial-range    = number ["." nz-number]
	 *                    ; partial FETCH.  The first number is
	 *                    ; the offset of the first byte,
	 *                    ; the second number is the length of
	 *                    ; the fragment.
	 */

	/* IMAP URL syntax is quite horrible to parse. It relies upon the
	   generic URI path resolution, but the icommand syntax also relies on
	   ';' separators. We use the generic URI path parse functions to
	   adhere to the URI path resolution rules and glue back together path
	   segments when these are part of the same (mailbox or section) value.
	*/

	mailbox = t_str_new(256);
	segment = path;

	/* Resolve relative URI path; determine what to copy from the base URI */
	if (url != NULL && url_parser->base != NULL && relative > 0) {
		const struct imap_url *base = url_parser->base;
		int rel = relative;

		/* /;PARTIAL= */
		if (base->have_partial && --rel <= 0) {
			have_partial = base->have_partial;
			partial_offset = base->partial_offset;
			partial_size = base->partial_size;
		}
		/* /;SECTION= */
		if (base->section != NULL) {
			p = base->section + strlen(base->section);
			/* determine what to retain from base section path */
			for (; p > base->section && rel > 0; p--) {
				if (*p =='/' && --rel <= 0) break; 
			}
			if (--rel <= 0 && p > base->section) {
				if (p[-1] == '/') section_endslash = TRUE;
				if (section == NULL)
					section = t_str_new(256);
				str_append_data(section, base->section, p-base->section);
			}
		}
		/* /;UID= */
		if (base->uid > 0 && --rel <= 0) {
			uid = base->uid;
		}
		/* /mail/box;UIDVALIDITY= */
		if (base->mailbox != NULL) {
			uidvalidity = base->uidvalidity;
			p = base->mailbox + strlen(base->mailbox);
			/* mailbox has implicit trailing '/' */
			if (p[-1] != '/' && base->uid == 0 && rel > 0)
				rel--;
			/* determine what to retain from base mailbox path */
			for (; p > base->mailbox && rel > 0; p--) {
				if (*p =='/') {
					uidvalidity = 0;
					if (--rel <= 0)
						break;
				}
			}
			if (--rel <= 0 && p > base->mailbox) {
				if (p[-1] == '/')
					mailbox_endslash = TRUE;
				str_append_data(mailbox, base->mailbox,
						p - base->mailbox);
			}
		}
	}

	/* Scan for last mailbox-ref segment */
	if (segment != NULL) {
		if (relative == 0 || (!have_partial && section == NULL)) {
			p = NULL;
			while (*segment != NULL) {
				/* ';' must be pct-encoded; if it is not, this is
					 either the last mailbox-ref path segment containing
					 ';UIDVALIDITY=' or the subsequent iuid ';UID=' path
					 segment */
				if ((p = strchr(*segment, ';')) != NULL)
					break;

				if (**segment != '\0') {
					if (segment > path ||
							(!mailbox_endslash && str_len(mailbox) > 0))
						str_append_c(mailbox, '/');
					if (!uri_data_decode(parser, *segment, NULL, &value))
						return -1;
					str_append(mailbox, value);
					mailbox_endslash = FALSE;
				}
				segment++;
			}

			/* Handle ';' */
			if (p != NULL) {
				/* [uidvalidity] */
				if (strncasecmp(p, ";UIDVALIDITY=", 13) == 0) {
					/* append last bit of mailbox */
					if (*segment != p) {
						if (segment > path ||
								(!mailbox_endslash && str_len(mailbox) > 0))
							str_append_c(mailbox, '/');
						if (!uri_data_decode(parser, *segment, p, &value))
							return -1;
						str_append(mailbox, value);
					}

					/* ";UIDVALIDITY=" nz-number */
					if (strchr(p+13, ';') != NULL) {
						parser->error = "Encountered stray ';' after UIDVALIDITY";
						return -1;
					}

					/* nz-number */
					if (p[13] == '\0') {
						parser->error = "Empty UIDVALIDITY value";
						return -1;
					}
					if (imap_url_parse_number(parser, p+13, &uidvalidity) <= 0)
						return -1;
					if (uidvalidity == 0) {
						parser->error = "UIDVALIDITY cannot be zero";
						return -1;
					}
					segment++;
				} else if (p != *segment) {
					parser->error = "Encountered stray ';' in mailbox reference";
					return -1;
				}
			}

			/* iuid */
		 	if (*segment != NULL && strncasecmp(*segment, ";UID=", 5) == 0) {
				/* ";UID=" nz-number */
				value = (*segment)+5;
				if ((p = strchr(value,';')) != NULL) {
					if (segment[1] != NULL ) {
						/* not the last segment, so it cannot be extension like iurlauth */
						parser->error = "Encountered stray ';' in UID path segment";
						return -1;
					}
					urlext = p;
					value = t_strdup_until(value, p);
				}
				/* nz-number */
				if (*value == '\0') {
					parser->error = "Empty UID value";
					return -1;
				}
				if (imap_url_parse_number(parser, value, &uid) <= 0)
					return -1;
				if (uid == 0) {
					parser->error = "UID cannot be zero";
					return -1;
				}
				segment++;
			}
		}

		/* [isection] [ipartial] */
		if (*segment != NULL && uid > 0) {
			/* [isection] */
			if (section != NULL ||
				  strncasecmp(*segment, ";SECTION=", 9) == 0) {
				/* ";SECTION=" enc-section */
				if (section == NULL) {
					section = t_str_new(256);
					value = (*segment) + 9;
				} else {
					value = *segment;
				}

				/* enc-section can contain slashes, so we merge path segments until one
					 contains ';' */
				while ((p = strchr(value,';')) == NULL) {
					if (!section_endslash && str_len(section) > 0)
						str_append_c(section, '/');
					if (*value != '\0') {
						if (!uri_data_decode(parser, value, NULL, &value))
							return -1;
						str_append(section, value);
						section_endslash = FALSE;
					}

					segment++;
					if (*segment == NULL)
						break;
					value = *segment;
				}

				if (p != NULL) {
					/* found ';' */
					if (p != value) {
						/* it is not at the beginning of the path segment */
						if (segment[1] != NULL) {
							/* not the last segment, so it cannot be extension like iurlauth */
							parser->error = "Encountered stray ';' in SECTION path segment";
							return -1;
						}
						urlext = p;
						value = t_strdup_until(value, p);
						if (!section_endslash && str_len(section) > 0)
							str_append_c(section, '/');
						if (!uri_data_decode(parser, value, NULL, &value))
							return -1;
						str_append(section, value);
						segment++;
					}
				}

				if (str_len(section) == 0) {
					parser->error = "Empty SECTION value";
					return -1;
				}
			}

			/* [ipartial] */
			if (*segment != NULL &&
				  strncasecmp(*segment, ";PARTIAL=", 9) == 0) {
				have_partial = TRUE;

				/* ";PARTIAL=" partial-range */
				value = (*segment) + 9;
				if ((p = strchr(value,';')) != NULL) {
					urlext = p;
					value = t_strdup_until(value, p);
				}
				if (*value == '\0') {
					parser->error = "Empty PARTIAL value";
					return -1;
				}
				/* partial-range = number ["." nz-number] */
				if ((p = strchr(value,'.')) != NULL) {
					if (p[1] == '\0') {
						parser->error = "Empty PARTIAL size";
						return -1;
					}
					if (imap_url_parse_offset(parser, p+1, &partial_size) <= 0)
						return -1;
					if (partial_size == 0) {
						parser->error = "PARTIAL size cannot be zero";
						return -1;
					}
					value = t_strdup_until(value, p);
					if (*value == '\0') {
						parser->error = "Empty PARTIAL offset";
						return -1;
					}
				}
				if (imap_url_parse_offset(parser,value, &partial_offset) <= 0)
					return -1;
				segment++;
			}
		}

		if (*segment != NULL) {
			if (urlext != NULL || **segment != '\0' || *(segment+1) != NULL ) {
				parser->error = t_strdup_printf(
					"Unexpected IMAP URL path segment: `%s'",
					str_sanitize(*segment, 80));
				return -1;
			}
		}
	}

	/* ";" {...} at end of URL */ 
	if (urlext != NULL) {
		/* [iurlauth] */
		if ((ret = imap_url_parse_urlauth(url_parser, urlext)) < 0)
			return ret;
		else if (ret == 0) {
			/* something else */
			parser->error = t_strdup_printf(
				"Unrecognized IMAP URL extension: %s",
				str_sanitize(urlext, 80));
			return -1;
		}
	}

	if (is_messagelist_r != NULL)
		*is_messagelist_r = (uid == 0);

	if (url != NULL) {
		if (str_len(mailbox) > 0)
			url->mailbox = p_strdup(parser->pool, str_c(mailbox));
		url->uidvalidity = uidvalidity;
		url->uid = uid;
		if (section != NULL)
			url->section = p_strdup(parser->pool, str_c(section));
		url->have_partial = have_partial;
		url->partial_offset = partial_offset;
		url->partial_size = partial_size;
	}
	return 1;
}

static bool imap_url_do_parse(struct imap_url_parser *url_parser)
{
	struct uri_parser *parser = &url_parser->parser;
	const char *const *path;
	bool is_messagelist = FALSE;
	bool have_scheme = FALSE;
	int relative;
	const char *query;
	int ret, sret;

	/*
	 * imapurl          = "imap://" iserver ipath-query
	 * 	                 ; Defines an absolute IMAP URL
	 * iserver          = [iuserinfo "@"] host [":" port]
	 *                    ; This is the same as "authority" defined
	 *                    ; in [URI-GEN].
	 * ipath-query      = ["/" [ icommand ]]
	 * 	                 ; Corresponds to "path-abempty [ "?" query ]" in
	 * 	                 ; [URI-GEN]
	 * icommand         = imessagelist /
	 *                    imessagepart [iurlauth]
	 * imessagelist     = imailbox-ref [ "?" enc-search ]
	 *                    ; "enc-search" is [URI-GEN] "query".
	 * imessagepart     = imailbox-ref iuid [isection] [ipartial]
	 * enc-search       = 1*bchar
	 *                    ; %-encoded version of [IMAPABNF]
	 *                    ; "search-program".  Note that IMAP4
	 *                    ; literals may not be used in
	 *                    ; a "search-program", i.e., only
	 *                    ; quoted or non-synchronizing
	 *                    ; literals (if the server supports
	 *                    ; LITERAL+ [LITERAL+]) are allowed.
	 */

	/* "imap:" */
	if ((url_parser->flags & IMAP_URL_PARSE_SCHEME_EXTERNAL) == 0) {
		const char *scheme;

		if (uri_parse_scheme(parser, &scheme) <= 0) {
			parser->cur = parser->begin;
		} else {
			if (strcasecmp(scheme, "imap") != 0) {
				parser->error = "Not an IMAP URL";
				return FALSE;
			}
			have_scheme = TRUE;
		}
	} else {
		have_scheme = TRUE;
	}

	/* "//" iserver */
	if ((sret = imap_url_parse_iserver(url_parser)) < 0)
		return FALSE;

	if (have_scheme && sret == 0) {
		parser->error = "Absolute IMAP URL requires `//' after `imap:'";
		return FALSE;
	}

	if (sret > 0 &&
	    (url_parser->flags & IMAP_URL_PARSE_REQUIRE_RELATIVE) != 0) {
		parser->error = "Relative URL required";
		return FALSE;
	}

	/* ipath-query      = ["/" [ icommand ]]  ; excludes `[ "?" enc-search ]` */
	if ((ret = uri_parse_path(parser, &relative, &path)) < 0)
		return FALSE;

	/* Relative urls are only valid when we have a base url */
	if (sret == 0) {
		if (url_parser->base == NULL) {
			parser->error = "Relative URL not allowed";
			return FALSE;
		} else if (url_parser->url != NULL) {
			struct imap_url *url = url_parser->url;
			const struct imap_url *base = url_parser->base;

			uri_host_copy(parser->pool, &url->host, &base->host);
			url->port = base->port;
			url->userid = p_strdup_empty(parser->pool, base->userid);
			url->auth_type = p_strdup_empty(parser->pool, base->auth_type);
		}

		url_parser->relative = TRUE;
	}

	/* Parse path, i.e. `[ icommand ]` from `*( "/" segment )` */
	if (ret > 0 || url_parser->relative) {
		if (imap_url_parse_path(url_parser, path, relative,
					&is_messagelist) < 0)
			return FALSE;
	}

	/* [ "?" enc-search ] */
	if ((ret = uri_parse_query(parser, &query)) != 0) {
		if (ret < 0)
			return FALSE;

		if (!is_messagelist) {
			parser->error =
				"Search query part only valid for messagelist-type IMAP URL";
			return FALSE;
		} else if (*query == '\0') {
			parser->error = "Empty IMAP URL search query not allowed";
			return FALSE;
		}

		if (url_parser->url != NULL) {
			if (!uri_data_decode(parser, query, NULL, &query))
				return FALSE;
			url_parser->url->search_program =
				p_strdup(parser->pool, query);
		}
	}

	/* IMAP URL has no fragment */
	if ((ret = uri_parse_fragment(parser, &query)) != 0) {
		if (ret == 1)
			parser->error = "Fragment component not allowed in IMAP URL";
		return FALSE;
	}

	/* must be at end of URL now */
	i_assert(parser->cur == parser->end);

	return TRUE;
}

/* Public API */

int imap_url_parse(const char *url, const struct imap_url *base,
		   enum imap_url_parse_flags flags,
		   struct imap_url **url_r, const char **error_r)
{
	struct imap_url_parser url_parser;

	/* base != NULL indicates whether relative URLs are allowed. However, certain
	   flags may also dictate whether relative URLs are allowed/required. */
	i_assert((flags & IMAP_URL_PARSE_REQUIRE_RELATIVE) == 0 || base != NULL);
	i_assert((flags & IMAP_URL_PARSE_SCHEME_EXTERNAL) == 0 || base == NULL);

	i_zero(&url_parser);
	uri_parser_init(&url_parser.parser, pool_datastack_create(), url);

	url_parser.url = t_new(struct imap_url, 1);
	url_parser.url->uauth_expire = (time_t)-1;
	url_parser.base = base;
	url_parser.flags = flags;

	if (!imap_url_do_parse(&url_parser)) {
		*error_r = url_parser.parser.error;
		return -1;
	}
	*url_r = url_parser.url;
	return 0;
}

/*
 * IMAP URL construction
 */

static void
imap_url_append_mailbox(const struct imap_url *url, string_t *urlstr)
{
	uri_append_path_data(urlstr, ";", url->mailbox);
	if (url->uidvalidity != 0)
		str_printfa(urlstr, ";UIDVALIDITY=%u", url->uidvalidity);
	if (url->uid == 0) {
		/* message list */
		if (url->search_program != NULL) {
			str_append_c(urlstr, '?');
			uri_append_query_data(urlstr, ";", url->search_program);
		}
	} else {
		/* message part */
		str_printfa(urlstr, "/;UID=%u", url->uid);
		if (url->section != NULL) {
			str_append(urlstr, "/;SECTION=");
			uri_append_path_data(urlstr, ";", url->section);
		}
		if (url->have_partial) {
			str_append(urlstr, "/;PARTIAL=");
			if (url->partial_size == 0) {
				str_printfa(urlstr, "%"PRIuUOFF_T,
					    url->partial_offset);
			} else {
				str_printfa(urlstr, "%"PRIuUOFF_T".%"PRIuUOFF_T,
					    url->partial_offset,
					    url->partial_size);
			}
		}

		/* urlauth */
		if (url->uauth_access_application != NULL) {
			if (url->uauth_expire != (time_t)-1) {
				str_append(urlstr, ";EXPIRE=");
				str_append(urlstr, iso8601_date_create(url->uauth_expire));
			}
			str_append(urlstr, ";URLAUTH=");
			str_append(urlstr, url->uauth_access_application);
			if (url->uauth_access_user != NULL) {
				str_append_c(urlstr, '+');
				uri_append_user_data(urlstr, ";",
						     url->uauth_access_user);
			}
		}
	}
}

const char *imap_url_create(const struct imap_url *url)
{
	string_t *urlstr = t_str_new(512);

	/* scheme */
	uri_append_scheme(urlstr, "imap");
	str_append(urlstr, "//");

	/* user */
	if (url->userid != NULL || url->auth_type != NULL) {
		if (url->userid != NULL)
			uri_append_user_data(urlstr, ";:", url->userid);
		if (url->auth_type != NULL) {
			str_append(urlstr, ";AUTH=");
			uri_append_user_data(urlstr, ";:", url->auth_type);
		}
		str_append_c(urlstr, '@');
	}

	/* server */
	uri_append_host(urlstr, &url->host);
	uri_append_port(urlstr, url->port);

	/* Older syntax (RFC 2192) requires this slash at all times */
	str_append_c(urlstr, '/');

	/* mailbox */
	if (url->mailbox != NULL)
		imap_url_append_mailbox(url, urlstr);
	return str_c(urlstr);
}

const char *
imap_url_add_urlauth(const char *rumpurl, const char *mechanism,
		     const unsigned char *token, size_t token_len)
{
	return t_strconcat(rumpurl, ":", t_str_lcase(mechanism), ":",
			   binary_to_hex(token, token_len), NULL);
}
