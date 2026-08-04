/* Copyright (c) Dovecot authors, see top-level COPYING file */

/*
 * JSON Pointer parser and evaluator - RFC 6901.
 *
 * RFC 6901 sect 3 (Syntax) ABNF:
 *
 *   json-pointer    = *( "/" reference-token )
 *   reference-token = *( unescaped / escaped )
 *   unescaped       = %x00-2E / %x30-7D / %x7F-10FFFF
 *			; %x2F ('/') and %x7E ('~') are excluded
 *   escaped	 = "~" ( "0" / "1" )
 *			; "~0" -> '~', "~1" -> '/'
 *
 * RFC 6901 sect 4 (Evaluation): the escape sequences "~1" and "~0" MUST be
 * decoded in that order - "~1" first, then "~0" - to avoid misinterpreting
 * a literal "~1" that resulted from decoding "~01".
 *
 * RFC 6901 sect 4 array-index ABNF:
 *
 *   array-index     = %x30 / ( %x31-39 *(%x30-39) )
 *			; "0", or [1-9][0-9]* (no leading zeros)
 *
 * RFC 6901 sect 6 (URI Fragment Identifier Representation): a JSON Pointer
 * embedded in a URI fragment is UTF-8 encoded with characters disallowed
 * by RFC 3986's fragment rule percent-encoded.  Decoding reverses the
 * percent-encoding before applying the sect 3/sect 4 grammar.
 */

#include "lib.h"
#include "buffer.h"
#include "numpack.h"
#include "uri-util.h"
#include "str.h"

#include "json-pointer.h"

/* On-disk binary format:
       magic      = "JPTR"	   4 bytes
       version    = 0x01	     1 byte
       step_count = numpack uint     1..N bytes
       step       = numpack token_len + token_len bytes  (repeated step_count times)
   Lengths use numpack (src/lib/numpack.h) so embedded NULs in tokens
   round-trip safely.  Import treats the buffer as untrusted; the caps
   below bound stack/heap usage from a malicious blob. */
static const char json_pointer_magic[4] = { 'J', 'P', 'T', 'R' };
#define JSON_POINTER_FORMAT_VERSION 0x01

/* Bounds to clamp untrusted input.  Both well above any realistic JSON
   Pointer; the limits exist purely to refuse pathological blobs without
   any allocation attempt. */
#define JSON_POINTER_IMPORT_MAX_STEPS  4096
#define JSON_POINTER_IMPORT_MAX_TOKEN  (64 * 1024)

/* Parse a NUL-terminated JSON Pointer string into compiled form.

   Grammar (RFC 6901 sect 3):
     json-pointer    = *( "/" reference-token )
     reference-token = *( unescaped / escaped )
     escaped	 = "~" ( "0" / "1" )

   Evaluation rule (RFC 6901 sect 4): split on '/', then within each token
   expand "~1" -> '/' first, then "~0" -> '~'.  Order matters: doing it
   the other way would let a literal "~01" decode incorrectly to '/'.

   A '~' not followed by '0' or '1' violates the `escaped` production
   and is rejected as a syntax error. */
static int
json_pointer_parse(const char *pointer, struct json_pointer **pointer_r,
		   const char **error_r)
{
	pool_t pool;
	struct json_pointer *jpointer;
	struct json_pointer_step **tail;
	const char *p = pointer;

	if (*p != '\0' && *p != '/') {
		*error_r = "JSON Pointer must be empty or start with '/'";
		return -1;
	}

	pool = pool_alloconly_create("json pointer", 256);
	jpointer = p_new(pool, struct json_pointer, 1);
	jpointer->pool = pool;
	tail = &jpointer->first;

	while (*p == '/') {
		struct json_pointer_step *step;
		const char *seg_start;
		string_t *tok;

		p++; /* skip '/' */
		seg_start = p;

		p = strchr(seg_start, '/');
		if (p == NULL)
			p = CONST_PTR_OFFSET(seg_start, strlen(seg_start));

		tok = str_new(pool, (size_t)(p - seg_start) + 1);
		for (const char *q = seg_start; q < p; q++) {
			if (*q != '~') {
				str_append_c(tok, *q);
				continue;
			}
			q++;
			if (q >= p) {
				*error_r = "Invalid escape sequence in JSON Pointer";
				pool_unref(&pool);
				return -1;
			}
			if (*q == '0')
				str_append_c(tok, '~');
			else if (*q == '1')
				str_append_c(tok, '/');
			else {
				*error_r = "Invalid escape sequence in JSON Pointer";
				pool_unref(&pool);
				return -1;
			}
		}

		step = p_new(pool, struct json_pointer_step, 1);
		step->token_len = str_len(tok);
		step->token = str_c(tok);
		*tail = step;
		tail = &step->next;
	}

	i_assert(*p == '\0');
	*pointer_r = jpointer;
	return 0;
}

int json_pointer_create(const char *pointer, struct json_pointer **pointer_r,
		     const char **error_r)
{
	i_assert(pointer != NULL);
	return json_pointer_parse(pointer, pointer_r, error_r);
}

/* Parse a JSON Pointer carried in a URI fragment (RFC 6901 sect 6).

   The input begins with '#'.  The remainder is UTF-8 octets with any
   character disallowed by the RFC 3986 `fragment` production percent-
   encoded as "%HH".  Decode the percent-encoding here, then hand the
   resulting JSON-string-form pointer to json_pointer_parse() (sect 3/sect 4). */
int json_pointer_create_uri_fragment(const char *fragment,
				     struct json_pointer **pointer_r,
				     const char **error_r)
{
	struct uri_parser parser;
	const char *decoded;
	pool_t pool;
	int ret;

	i_assert(fragment != NULL);

	size_t len = strlen(fragment);
	pool = pool_datastack_create();
	uri_parser_init_data(&parser, pool, (const unsigned char *)fragment, len);
	ret = uri_parse_fragment(&parser, &decoded);

	if (ret == 1) {
		if (!uri_data_decode(&parser, decoded, NULL, &decoded)) {
			*error_r = t_strdup(parser.error);
			return -1;
		}
		ret = json_pointer_parse(decoded, pointer_r, error_r);
	} else if (ret == 0) {
		*error_r = "URI fragment must begin with '#'";
		ret = -1;
	} else
		*error_r = t_strdup(parser.error);

	return ret;
}

void json_pointer_free(struct json_pointer **_pointer)
{
	struct json_pointer *pointer = *_pointer;

	if (pointer == NULL)
		return;
	*_pointer = NULL;
	pool_unref(&pointer->pool);
}

/* --- Binary export / import --- */

int json_pointer_export(buffer_t *dest, const struct json_pointer *pointer,
			const char **error_r)
{
	unsigned int step_count = 0;

	i_assert(dest != NULL);
	i_assert(pointer != NULL);
	i_assert(error_r != NULL);

	for (const struct json_pointer_step *s = pointer->first; s != NULL;
	     s = s->next) {
		step_count++;
		if (s->token_len > JSON_POINTER_IMPORT_MAX_TOKEN) {
			*error_r = "JSON pointer token length exceeds cap";
			return -1;
		}
	}
	if (step_count > JSON_POINTER_IMPORT_MAX_STEPS) {
		*error_r = "JSON pointer step count exceeds cap";
		return -1;
	}

	buffer_append(dest, json_pointer_magic, sizeof(json_pointer_magic));
	buffer_append_c(dest, JSON_POINTER_FORMAT_VERSION);
	numpack_encode(dest, step_count);

	for (const struct json_pointer_step *s = pointer->first; s != NULL;
	     s = s->next) {
		numpack_encode(dest, s->token_len);
		buffer_append(dest, s->token, s->token_len);
	}
	return 0;
}

int json_pointer_import(const void *data, size_t size,
			struct json_pointer **pointer_r, const char **error_r)
{
	const unsigned char *p = data;
	/* data == NULL, size == 0 is a valid input (asserted below), but
	   NULL + 0 is UB - only form the pointer when there's anything to
	   point past. */
	const unsigned char *end = (size == 0 ? p : p + size);
	uint64_t step_count, i;
	pool_t pool;
	struct json_pointer *jpointer;
	struct json_pointer_step **tail;

	i_assert(data != NULL || size == 0);
	i_assert(pointer_r != NULL);
	i_assert(error_r != NULL);

	if ((size_t)(end - p) < sizeof(json_pointer_magic) + 1) {
		*error_r = "Truncated JSON pointer header";
		return -1;
	}
	if (memcmp(p, json_pointer_magic, sizeof(json_pointer_magic)) != 0) {
		*error_r = "Bad JSON pointer magic";
		return -1;
	}
	p += sizeof(json_pointer_magic);
	if (*p != JSON_POINTER_FORMAT_VERSION) {
		*error_r = "Unsupported JSON pointer format version";
		return -1;
	}
	p++;

	if (numpack_decode(&p, end, &step_count) < 0) {
		*error_r = "Truncated JSON pointer step count";
		return -1;
	}
	if (step_count > JSON_POINTER_IMPORT_MAX_STEPS) {
		*error_r = "JSON pointer step count exceeds cap";
		return -1;
	}
	/* Each step is at least 1 byte (numpack length of 0). */
	if (step_count > (uint64_t)(end - p)) {
		*error_r = "Truncated JSON pointer step list";
		return -1;
	}

	/* Size the initial block from the validated step_count and the caps,
	   not directly from `size`: `size` is the attacker-controlled length
	   of the blob being imported, and a crafted blob (tiny header,
	   step_count=0, gigabytes of padding) would otherwise allocate the
	   full blob size here before the trailing-data check below rejects
	   it. I_MIN keeps single-block allocation for legitimate blobs. */
	pool = pool_alloconly_create(
		"json pointer",
		256 + I_MIN(size, (size_t)step_count *
				  (JSON_POINTER_IMPORT_MAX_TOKEN +
				   sizeof(struct json_pointer_step))));
	jpointer = p_new(pool, struct json_pointer, 1);
	jpointer->pool = pool;
	tail = &jpointer->first;

	for (i = 0; i < step_count; i++) {
		uint64_t token_len;
		struct json_pointer_step *step;

		if (numpack_decode(&p, end, &token_len) < 0) {
			*error_r = "Truncated JSON pointer token length";
			pool_unref(&pool);
			return -1;
		}
		if (token_len > JSON_POINTER_IMPORT_MAX_TOKEN) {
			*error_r = "JSON pointer token length exceeds cap";
			pool_unref(&pool);
			return -1;
		}
		if (token_len > (uint64_t)(end - p)) {
			*error_r = "Truncated JSON pointer token";
			pool_unref(&pool);
			return -1;
		}

		step = p_new(pool, struct json_pointer_step, 1);
		step->token_len = token_len;
		if (token_len == 0) {
			/* Empty token - keep `token` pointing to a stable
			   NUL byte so callers comparing against C strings
			   still see a valid pointer. */
			step->token = "";
		} else {
			char *token = p_malloc(pool, token_len + 1);
			memcpy(token, p, token_len);
			token[token_len] = '\0';
			step->token = token;
		}
		p += token_len;

		*tail = step;
		tail = &step->next;
	}

	if (p != end) {
		*error_r = "Trailing data after JSON pointer";
		pool_unref(&pool);
		return -1;
	}

	*pointer_r = jpointer;
	return 0;
}

bool
json_pointer_token_parse_array_index(const char *token, size_t token_len,
				     unsigned int *idx_r)
{
	const unsigned char *end_p;
	uintmax_t idx;

	if (token_len == 0)
		return FALSE;
	if (token[0] == '0') {
		if (token_len != 1)
			return FALSE; /* leading zero */
		*idx_r = 0;
		return TRUE;
	}
	if (token[0] < '1' || token[0] > '9')
		return FALSE;
	if (str_parse_data_uintmax((const unsigned char *)token, token_len,
				   &idx, &end_p) < 0)
		return FALSE;
	if (end_p != (const unsigned char *)token + token_len)
		return FALSE;
	if (idx > UINT_MAX)
		return FALSE;
	*idx_r = (unsigned int)idx;
	return TRUE;
}
