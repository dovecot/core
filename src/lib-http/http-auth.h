#ifndef HTTP_AUTH_H
#define HTTP_AUTH_H

#include "array-decl.h"

struct http_auth_param;
struct http_auth_challenge;
struct http_auth_credentials;

ARRAY_DEFINE_TYPE(http_auth_param, struct http_auth_param);
ARRAY_DEFINE_TYPE(http_auth_challenge, struct http_auth_challenge);

struct http_auth_param {
	const char *name;
	const char *value;
};

struct http_auth_challenge {
	const char *scheme;
	const char *data;
	ARRAY_TYPE(http_auth_param) params;
};

struct http_auth_credentials {
	const char *scheme;
	const char *data;
	ARRAY_TYPE(http_auth_param) params;
};

/*
 * Parsing
 */

int http_auth_parse_challenges(const unsigned char *data, size_t size,
	ARRAY_TYPE(http_auth_challenge) *chlngs);
int http_auth_parse_credentials(const unsigned char *data, size_t size,
	struct http_auth_credentials *crdts);

/*
 * Construction
 */

void http_auth_create_challenge(string_t *out,
	const struct http_auth_challenge *chlng);
void http_auth_create_challenges(string_t *out,
	const ARRAY_TYPE(http_auth_challenge) *chlngs);

void http_auth_create_credentials(string_t *out,
	const struct http_auth_credentials *crdts);

/*
 * Manipulation
 */

void http_auth_challenge_copy(pool_t pool,
	struct http_auth_challenge *dst,
	const struct http_auth_challenge *src);
struct http_auth_challenge *
http_auth_challenge_clone(pool_t pool,
	const struct http_auth_challenge *src);

void http_auth_credentials_copy(pool_t pool,
	struct http_auth_credentials *dst,
	const struct http_auth_credentials *src);
struct http_auth_credentials *
http_auth_credentials_clone(pool_t pool,
	const struct http_auth_credentials *src);

/*
 * Simple schemes
 */

void http_auth_basic_challenge_init(struct http_auth_challenge *chlng,
	const char *realm);
void http_auth_basic_credentials_init(struct http_auth_credentials *crdts,
	const char *username, const char *password);

#endif

