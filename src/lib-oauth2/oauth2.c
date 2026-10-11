/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "array.h"
#include "buffer.h"
#include "str.h"
#include "istream.h"
#include "json-istream.h"
#include "json-tree-io.h"
#include "uri-util.h"
#include "var-expand.h"
#include "var-expand-split.h"
#include "oauth2.h"
#include "oauth2-private.h"
#include <ctype.h>

int oauth2_json_tree_build(const buffer_t *json, struct json_tree **jtree_r,
			   const char **error_r)
{
	return json_tree_read_buffer(json, 0, jtree_r, error_r);
}

bool oauth2_valid_token(const char *token)
{
	if (token == NULL || *token == '\0' || strpbrk(token, "\r\n") != NULL)
		return FALSE;
	return TRUE;
}

#define OAUTH2_URL_PLACEMENT_ERROR \
	"%{access_token} must be in the URL path or query"

enum oauth2_url_scan_state {
	/* Before "//" or the first "/", "?" or "#" */
	OAUTH2_URL_SCAN_START,
	/* After "//", before the next "/", "?" or "#" */
	OAUTH2_URL_SCAN_AUTHORITY,
	OAUTH2_URL_SCAN_PATH,
	/* After "#" */
	OAUTH2_URL_SCAN_FRAGMENT,
};

struct oauth2_url_scan {
	enum oauth2_url_scan_state state;
	/* First variable in the authority without the safe filter. It is
	   fine if it turns out to be userinfo, which "@" tells. */
	const char *authority_var;
	/* First variable that needs the safe filter but doesn't have it. */
	const char *unsafe_var;
};

static void oauth2_url_scan_literal(struct oauth2_url_scan *scan,
				    const char *literal)
{
	for (; *literal != '\0'; literal++) {
		switch (scan->state) {
		case OAUTH2_URL_SCAN_START:
			if (literal[0] == '/' && literal[1] == '/') {
				scan->state = OAUTH2_URL_SCAN_AUTHORITY;
				literal++;
			} else if (*literal == '/' || *literal == '?') {
				scan->state = OAUTH2_URL_SCAN_PATH;
			} else if (*literal == '#') {
				scan->state = OAUTH2_URL_SCAN_FRAGMENT;
			}
			break;
		case OAUTH2_URL_SCAN_AUTHORITY:
			if (*literal == '@') {
				scan->authority_var = NULL;
			} else if (*literal == '/' || *literal == '?' ||
				   *literal == '#') {
				scan->state = *literal == '#' ?
					OAUTH2_URL_SCAN_FRAGMENT :
					OAUTH2_URL_SCAN_PATH;
				if (scan->unsafe_var == NULL)
					scan->unsafe_var = scan->authority_var;
				scan->authority_var = NULL;
			}
			break;
		case OAUTH2_URL_SCAN_PATH:
			if (*literal == '#')
				scan->state = OAUTH2_URL_SCAN_FRAGMENT;
			break;
		case OAUTH2_URL_SCAN_FRAGMENT:
			return;
		}
	}
}

int oauth2_url_template_check(const struct var_expand_program *url_template,
			      const char **error_r)
{
	pool_t pool = pool_datastack_create();
	ARRAY_TYPE(const_string) literals;
	ARRAY_TYPE(const_expansion_program) parts;
	struct oauth2_url_scan scan = { .state = OAUTH2_URL_SCAN_START };
	const struct var_expand_program *const *part;
	unsigned int i = 0;

	i_assert(url_template != NULL);

	p_array_init(&literals, pool, 4);
	p_array_init(&parts, pool, 4);
	var_expand_program_pieces(pool, url_template, &literals, &parts);

	array_foreach(&parts, part) {
		oauth2_url_scan_literal(&scan, array_idx_elem(&literals, i++));
		if (scan.state == OAUTH2_URL_SCAN_PATH)
			continue;
		if (var_expand_program_has_variable(*part, "access_token",
						    TRUE)) {
			*error_r = OAUTH2_URL_PLACEMENT_ERROR;
			return -1;
		}
		if (scan.state == OAUTH2_URL_SCAN_FRAGMENT ||
		    var_expand_program_has_filter(*part, "safe"))
			continue;
		const char *name = var_expand_program_to_string_one(*part);
		if (scan.state == OAUTH2_URL_SCAN_START) {
			if (scan.unsafe_var == NULL)
				scan.unsafe_var = name;
		} else if (scan.authority_var == NULL) {
			scan.authority_var = name;
		}
	}
	oauth2_url_scan_literal(&scan, array_idx_elem(&literals, i));
	if (scan.state == OAUTH2_URL_SCAN_AUTHORITY &&
	    scan.unsafe_var == NULL)
		scan.unsafe_var = scan.authority_var;

	if (scan.unsafe_var != NULL) {
		/* name is "%{...}", the filter goes before the closing brace */
		*error_r = t_strdup_printf(
			"%s is part of the URL scheme or host and needs the "
			"safe filter, use %.*s|safe}", scan.unsafe_var,
			(int)strlen(scan.unsafe_var) - 1, scan.unsafe_var);
		return -1;
	}
	return 0;
}

static int oauth2_url_escape(const char *input, const char **output_r,
			     void *context ATTR_UNUSED, const char **error_r)
{
	/* A dot segment would let the server resolve the URL path to
	   something else than intended. */
	if (strcmp(input, ".") == 0 || strcmp(input, "..") == 0) {
		*error_r = "Invalid token";
		return -1;
	}

	string_t *escaped = t_str_new(strlen(input) + 8);
	uri_append_unreserved(escaped, input);
	*output_r = str_c(escaped);
	return 0;
}

/* Returns TRUE if the first len bytes of url are scheme://authority
   followed by "/" or "?", with a non-empty host and no fragment. */
static bool oauth2_url_has_base(const char *url, size_t len)
{
	struct uri_parser parser;
	struct uri_authority auth;

	uri_parser_init_data(&parser, pool_datastack_create(),
			     (const unsigned char *)url, len);
	if (uri_parse_scheme(&parser, NULL) <= 0 ||
	    uri_parse_slashslash_host_authority(&parser, &auth) <= 0)
		return FALSE;
	return auth.host.name != NULL && auth.host.name[0] != '\0' &&
		parser.cur < parser.end &&
		(*parser.cur == '/' || *parser.cur == '?') &&
		memchr(parser.cur, '#', parser.end - parser.cur) == NULL;
}

int oauth2_url_template_expand(const struct var_expand_program *url_template,
			       const char *token, string_t *dest,
			       const char **error_r)
{
	const struct var_expand_table table[] = {
		{ .key = "access_token", .value = token },
		VAR_EXPAND_TABLE_END
	};
	const struct var_expand_params params = {
		.table = table,
		.escape_func = oauth2_url_escape,
	};
	pool_t pool = pool_datastack_create();
	ARRAY_TYPE(const_string) literals;
	ARRAY_TYPE(const_expansion_program) parts;
	const struct var_expand_program *const *part;
	string_t *url = t_str_new(128);
	size_t base_len = 0;
	bool token_seen = FALSE;
	unsigned int i = 0;

	i_assert(url_template != NULL);

	p_array_init(&literals, pool, 4);
	p_array_init(&parts, pool, 4);
	var_expand_program_pieces(pool, url_template, &literals, &parts);

	array_foreach(&parts, part) {
		str_append(url, array_idx_elem(&literals, i++));
		if (!token_seen &&
		    var_expand_program_has_variable(*part, "access_token",
						    TRUE)) {
			token_seen = TRUE;
			base_len = str_len(url);
		}
		if (var_expand_program_execute_one(url, *part, &params,
						   error_r) < 0)
			return -1;
	}
	str_append(url, array_idx_elem(&literals, i));

	/* The template check can't see what the variables expand to. */
	if (token_seen && !oauth2_url_has_base(str_c(url), base_len)) {
		*error_r = OAUTH2_URL_PLACEMENT_ERROR;
		return -1;
	}
	str_append_str(dest, url);
	return 0;
}
