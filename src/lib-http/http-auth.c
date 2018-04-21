/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "base64.h"
#include "array.h"
#include "http-parser.h"

#include "http-auth.h"

/* RFC 7235, Section 2.1:

   challenge      = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
   credentials    = auth-scheme [ 1*SP ( token68 / #auth-param ) ]

   auth-scheme    = token
   auth-param     = token BWS "=" BWS ( token / quoted-string )
   token68        = 1*( ALPHA / DIGIT /
                      "-" / "." / "_" / "~" / "+" / "/" ) *"="

   OWS            = *( SP / HTAB )
                  ; optional whitespace
   BWS            = OWS
                  ; "bad" whitespace
 */

/*
 * Parsing
 */

static int
http_parse_token68(struct http_parser *parser, const char **token68_r)
{
	const unsigned char *first;

	/* token68        = 1*( ALPHA / DIGIT /
                      "-" / "." / "_" / "~" / "+" / "/" ) *"="
	 */

	/* 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) */
	if (parser->cur >= parser->end || !http_char_is_token68(*parser->cur))
		return 0;
	first = parser->cur++;
	while (parser->cur < parser->end && http_char_is_token68(*parser->cur))
		parser->cur++;

	/* *"=" */
	while (parser->cur < parser->end && *parser->cur == '=')
		parser->cur++;
	
	*token68_r = t_strndup(first, parser->cur - first);
	return 1;
}

static int
http_parse_auth_param(struct http_parser *parser,
	const char **param_r, const char **value_r)
{
	const unsigned char *first = parser->cur, *end_token;
	int ret;

	/* auth-param     = token BWS "=" BWS ( token / quoted-string ) */

	/* token */
	if ((ret=http_parser_skip_token(parser)) <= 0) {
		parser->cur = first;
		return ret;
	}
	end_token = parser->cur;

	/* BWS "=" BWS */
	http_parse_ows(parser);
	if (parser->cur >= parser->end || *parser->cur != '=') {
		parser->cur = first;
		return 0;
	}
	parser->cur++;
	http_parse_ows(parser);

	/* ( token / quoted-string ) */
	if ((ret=http_parse_token_or_qstring(parser, value_r)) <= 0) {
		parser->cur = first;
		return ret;
	}

	*param_r = t_strndup(first, end_token - first);
	return 1;
}

static int
http_parse_auth_params(struct http_parser *parser,
	ARRAY_TYPE(http_auth_param) *params)
{
	const unsigned char *last = parser->cur;
	struct http_auth_param param;
	unsigned int count = 0;
	int ret;

	i_zero(&param);
	while ((ret=http_parse_auth_param
		(parser, &param.name, &param.value)) > 0) {
		if (!array_is_created(params))
			t_array_init(params, 4);
		array_append(params, &param, 1);
		count++;

		last = parser->cur;

		/* OWS "," OWS 
		   --> also allow empty elements
		 */
		for (;;) {
			http_parse_ows(parser);
			if (parser->cur >= parser->end || *parser->cur != ',')
				break;
			parser->cur++;
		}
	}
	
	parser->cur = last;
	if (ret < 0)
		return -1;
	return (count > 0 ? 1 : 0);
}

int http_auth_parse_challenges(const unsigned char *data, size_t size,
	ARRAY_TYPE(http_auth_challenge) *chlngs)
{
	struct http_parser parser;
	int ret;

	http_parser_init(&parser, data, size);

	/* WWW-Authenticate   = 1#challenge
	   Proxy-Authenticate = 1#challenge

	   challenge      = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
	   auth-scheme    = token
	 */

	/* 1#element => *( "," OWS ) ... ; RFC 7230, Section 7 */
	for (;;) {
		if (parser.cur >= parser.end || *parser.cur != ',')
			break;
		parser.cur++;
		http_parse_ows(&parser);
	}

	for (;;) {
		struct http_auth_challenge chlng;

		i_zero(&chlng);

		/* auth-scheme */
		if ((ret=http_parse_token(&parser, &chlng.scheme)) <= 0) {
			if (ret < 0)
				return -1;
			break;
		}

		/* [ 1*SP ... ] */
		if (parser.cur >= parser.end || *parser.cur != ' ')
			return 1;
		parser.cur++;
		while (parser.cur < parser.end && *parser.cur == ' ')
			parser.cur++;

		/* ( token68 / #auth-param ) */
		if ((ret=http_parse_auth_params(&parser, &chlng.params)) <= 0) {
			if (ret < 0)
				return -1;
			if (http_parse_token68(&parser, &chlng.data) < 0)
				return -1;
		}

		if (!array_is_created(chlngs))
			t_array_init(chlngs, 4);
		array_append(chlngs, &chlng, 1);

		/* OWS "," OWS 
		   --> also allow empty elements
		 */
		for (;;) {
			http_parse_ows(&parser);
			if (parser.cur >= parser.end || *parser.cur != ',')
				break;
			parser.cur++;
		}
	}

	if (parser.cur != parser.end)
		return -1;
	return 1;
}

int http_auth_parse_credentials(const unsigned char *data, size_t size,
	struct http_auth_credentials *crdts)
{
	struct http_parser parser;
	int ret;

	http_parser_init(&parser, data, size);

	/* Authorization       = credentials
	   Proxy-Authorization = credentials

	   credentials    = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
	   auth-scheme    = token
	 */

	i_zero(crdts);

	/* auth-scheme */
	if (http_parse_token(&parser, &crdts->scheme) <= 0)
		return -1;

	/* [ 1*SP ... ] */
	if (parser.cur >= parser.end || *parser.cur != ' ')
		return 1;
	parser.cur++;
	while (parser.cur < parser.end && *parser.cur == ' ')
		parser.cur++;

	/* ( token68 / #auth-param ) */
	if ((ret=http_parse_auth_params(&parser, &crdts->params)) <= 0) {
		if (ret < 0)
			return -1;
		if (http_parse_token68(&parser, &crdts->data) < 0)
			return -1;
	}

	if (parser.cur != parser.end)
		return -1;
	return 1;
}

/*
 * Construction
 */

static void
http_auth_create_param(string_t *out, const struct http_auth_param *param)
{
	const char *p, *first;

	/* auth-param     = token BWS "=" BWS ( token / quoted-string ) */

	str_append(out, param->name);
	str_append_c(out, '=');

	for (p = param->value; *p != '\0' && http_char_is_token(*p); p++);

	if ( *p != '\0' ) {
		str_append_c(out, '"');
		p = first = param->value;
		while (*p != '\0') {
			if (*p == '\\' || *p == '"') {
				str_append_data(out, first, p-first);
				str_append_c(out, '\\');
				first = p;
			}
			p++;
		}
		str_append_data(out, first, p-first);
		str_append_c(out, '"');
	} else {
		str_append(out, param->value);
	}
}

static void
http_auth_create_params(string_t *out,
	const ARRAY_TYPE(http_auth_param) *params)
{
	const struct http_auth_param *prms;
	unsigned int count, i;

	if (!array_is_created(params))
		return;

	prms = array_get(params, &count);
	for (i = 0; i < count; i++) {
		if (i > 0)
			str_append(out, ", ");
		http_auth_create_param(out, &prms[i]);
	}
}

static void http_auth_check_token68(const char *data)
{
	const char *p = data;

	/* Make sure we're not working with nonsense. */
	i_assert(http_char_is_token68(*p));
	for (p++; *p != '\0' && *p != '='; p++)
		i_assert(http_char_is_token68(*p));
	for (; *p != '\0'; p++)
		i_assert(*p == '=');
}

void http_auth_create_challenge(string_t *out,
	const struct http_auth_challenge *chlng)
{
	/* challenge      = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
	   auth-scheme    = token
	 */

	/* auth-scheme */
	str_append(out, chlng->scheme);

	if (chlng->data != NULL) {
		/* SP token68 */
		http_auth_check_token68(chlng->data);
		str_append_c(out, ' ');
		str_append(out, chlng->data);

	} else {
		/* SP #auth-param */
		str_append_c(out, ' ');
		http_auth_create_params(out, &chlng->params);
	}
}

void http_auth_create_challenges(string_t *out,
	const ARRAY_TYPE(http_auth_challenge) *chlngs)
{
	const struct http_auth_challenge *chlgs;
	unsigned int count, i;

	/* WWW-Authenticate   = 1#challenge
	   Proxy-Authenticate = 1#challenge
	 */
	chlgs = array_get(chlngs, &count);
	for (i = 0; i < count; i++) {
		if (i > 0)
			str_append(out, ", ");
		http_auth_create_challenge(out, &chlgs[i]);
	}	
}

void http_auth_create_credentials(string_t *out,
	const struct http_auth_credentials *crdts)
{
	/* Authorization       = credentials
	   Proxy-Authorization = credentials

	   credentials    = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
	   auth-scheme    = token
	 */

	/* auth-scheme */
	str_append(out, crdts->scheme);

	if (crdts->data != NULL) {
		/* SP token68 */
		http_auth_check_token68(crdts->data);
		str_append_c(out, ' ');
		str_append(out, crdts->data);

	} else {
		/* SP #auth-param */
		str_append_c(out, ' ');
		http_auth_create_params(out, &crdts->params);
	}
}

/*
 * Manipulation
 */

static void
http_auth_params_clone(pool_t pool,
	ARRAY_TYPE(http_auth_param) *dst,
	const ARRAY_TYPE(http_auth_param) *src)
{
	const struct http_auth_param *sparam;

	if (!array_is_created(src))
		return;

	p_array_init(dst, pool, 4);
	array_foreach(src, sparam) {
		struct http_auth_param nparam;

		i_zero(&nparam);
		nparam.name = p_strdup(pool, sparam->name);
		nparam.value = p_strdup(pool, sparam->value);

		array_append(dst, &nparam, 1);
	}
}

void http_auth_challenge_copy(pool_t pool,
	struct http_auth_challenge *dst,
	const struct http_auth_challenge *src)
{
	dst->scheme = p_strdup(pool, src->scheme);
	if (src->data != NULL)
		dst->data = p_strdup(pool, src->data);
	else
		http_auth_params_clone(pool, &dst->params, &src->params);
}

struct http_auth_challenge *
http_auth_challenge_clone(pool_t pool,
	const struct http_auth_challenge *src)
{
	struct http_auth_challenge *new;

	new = p_new(pool, struct http_auth_challenge, 1);
	http_auth_challenge_copy(pool, new, src);

	return new;
}

void http_auth_credentials_copy(pool_t pool,
	struct http_auth_credentials *dst,
	const struct http_auth_credentials *src)
{
	dst->scheme = p_strdup(pool, src->scheme);
	if (src->data != NULL)
		dst->data = p_strdup(pool, src->data);
	else
		http_auth_params_clone(pool, &dst->params, &src->params);
}

struct http_auth_credentials *
http_auth_credentials_clone(pool_t pool,
	const struct http_auth_credentials *src)
{
	struct http_auth_credentials *new;

	new = p_new(pool, struct http_auth_credentials, 1);
	http_auth_credentials_copy(pool, new, src);

	return new;
}

/*
 * Simple schemes
 */

void http_auth_basic_challenge_init(struct http_auth_challenge *chlng,
	const char *realm)
{
	i_zero(chlng);
	chlng->scheme = "Basic";
	if (realm != NULL) {
		struct http_auth_param param;

		i_zero(&param);
		param.name = "realm";
		param.value = t_strdup(realm);

		t_array_init(&chlng->params, 1);
		array_append(&chlng->params, &param, 1);
	}
}

void http_auth_basic_credentials_init(struct http_auth_credentials *crdts,
	const char *username, const char *password)
{
	const char *auth;
	string_t *data;

	i_assert(username != NULL && *username != '\0');
	i_assert(strchr(username, ':') == NULL);
 
	data = t_str_new(64);
	auth = t_strconcat(username, ":", password, NULL);
	base64_encode(auth, strlen(auth), data);

	i_zero(crdts);
	crdts->scheme = "Basic";
	crdts->data = str_c(data);
}
