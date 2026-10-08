/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "buffer.h"
#include "str.h"
#include "strescape.h"
#include "abnf.h"
#include "hmac.h"
#include "array.h"
#include "hash-method.h"
#include "istream.h"
#include "iso8601-date.h"
#include "json-tree.h"
#include "json-tree-io.h"
#include "json-ostream.h"
#include "array.h"
#include "base64.h"
#include "str-sanitize.h"
#include "dcrypt.h"
#include "oauth2.h"
#include "oauth2-private.h"
#include "dict.h"

#include <time.h>

enum oauth2_jwt_alg_type {
	OAUTH2_JWT_ALG_HMAC,
	OAUTH2_JWT_ALG_RSA,
	OAUTH2_JWT_ALG_EC,
};

struct oauth2_jwt_alg {
	const char *name;
	enum oauth2_jwt_alg_type type;
	const char *hash;
	/* RSA: PKCS#1 v1.5 or PSS padding */
	enum dcrypt_padding padding;
	/* EC: curve OID */
	const char *curve;
};

/* JWS algorithms (RFC 7518 3.1, RFC 8812 3.2) */
static const struct oauth2_jwt_alg oauth2_jwt_algs[] = {
	{ .name = "HS256", .type = OAUTH2_JWT_ALG_HMAC, .hash = "sha256" },
	{ .name = "HS384", .type = OAUTH2_JWT_ALG_HMAC, .hash = "sha384" },
	{ .name = "HS512", .type = OAUTH2_JWT_ALG_HMAC, .hash = "sha512" },
	{ .name = "RS256", .type = OAUTH2_JWT_ALG_RSA, .hash = "sha256",
	  .padding = DCRYPT_PADDING_RSA_PKCS1 },
	{ .name = "RS384", .type = OAUTH2_JWT_ALG_RSA, .hash = "sha384",
	  .padding = DCRYPT_PADDING_RSA_PKCS1 },
	{ .name = "RS512", .type = OAUTH2_JWT_ALG_RSA, .hash = "sha512",
	  .padding = DCRYPT_PADDING_RSA_PKCS1 },
	{ .name = "PS256", .type = OAUTH2_JWT_ALG_RSA, .hash = "sha256",
	  .padding = DCRYPT_PADDING_RSA_PKCS1_PSS },
	{ .name = "PS384", .type = OAUTH2_JWT_ALG_RSA, .hash = "sha384",
	  .padding = DCRYPT_PADDING_RSA_PKCS1_PSS },
	{ .name = "PS512", .type = OAUTH2_JWT_ALG_RSA, .hash = "sha512",
	  .padding = DCRYPT_PADDING_RSA_PKCS1_PSS },
	/* P-256 */
	{ .name = "ES256", .type = OAUTH2_JWT_ALG_EC, .hash = "sha256",
	  .curve = "1.2.840.10045.3.1.7" },
	/* P-384 */
	{ .name = "ES384", .type = OAUTH2_JWT_ALG_EC, .hash = "sha384",
	  .curve = "1.3.132.0.34" },
	/* P-521 */
	{ .name = "ES512", .type = OAUTH2_JWT_ALG_EC, .hash = "sha512",
	  .curve = "1.3.132.0.35" },
	/* secp256k1 */
	{ .name = "ES256K", .type = OAUTH2_JWT_ALG_EC, .hash = "sha256",
	  .curve = "1.3.132.0.10" },
};

static const struct oauth2_jwt_alg *oauth2_jwt_alg_find(const char *name)
{
	for (unsigned int i = 0; i < N_ELEMENTS(oauth2_jwt_algs); i++) {
		if (strcmp(oauth2_jwt_algs[i].name, name) == 0)
			return &oauth2_jwt_algs[i];
	}
	return NULL;
}

static bool
oauth2_jwt_alg_fits_key(const struct oauth2_jwt_alg *alg,
			enum dcrypt_key_type key_type, const char *curve)
{
	if (key_type == DCRYPT_KEY_RSA)
		return alg->type == OAUTH2_JWT_ALG_RSA;
	return alg->type == OAUTH2_JWT_ALG_EC && strcmp(alg->curve, curve) == 0;
}

/* RSA, or EC with *curve_r set to the curve OID. Other keys fail. */
static int
oauth2_jwt_key_type(struct dcrypt_public_key *key,
		    enum dcrypt_key_type *key_type_r, const char **curve_r,
		    const char **error_r)
{
	*key_type_r = dcrypt_key_type_public(key);
	*curve_r = NULL;
	if (*key_type_r == DCRYPT_KEY_EC) {
		if (!dcrypt_key_get_curve_public(key, curve_r, error_r))
			return -1;
	} else if (*key_type_r != DCRYPT_KEY_RSA) {
		*error_r = "Unsupported key type";
		return -1;
	}
	return 0;
}

static const struct json_tree_node *
get_field_node(const struct json_tree *tree, const char *key)
{
	const struct json_tree_node *root = json_tree_get_root_const(tree);
	const struct json_tree_node *value_node;

	value_node = json_tree_node_get_member(root, key);
	if (value_node == NULL ||
	    json_tree_node_is_object(value_node) ||
	    json_tree_node_is_array(value_node))
		return NULL;

	return value_node;
}

static const char *
get_field(const struct json_tree *tree, const char *key,
	  enum json_type *type_r)
{
	const struct json_tree_node *value_node = get_field_node(tree, key);

	if (value_node == NULL)
		return NULL;
	if (type_r != NULL)
		*type_r = json_tree_node_get_type(value_node);
	return json_tree_node_as_str(value_node);
}

static const char *
get_field_multiple(const struct json_tree *tree, const char *key)
{
	const struct json_tree_node *root = json_tree_get_root_const(tree);
	const struct json_tree_node *value_node;

	value_node = json_tree_node_get_member(root, key);
	if (value_node == NULL || json_tree_node_is_object(value_node))
		return NULL;
	if (!json_tree_node_is_array(value_node))
		return json_tree_node_as_str(value_node);

	const struct json_tree_node *entry_node;

	entry_node = json_tree_node_get_child(value_node);
	string_t *values = t_str_new(64);

	for (; entry_node != NULL;
	     entry_node = json_tree_node_get_next(entry_node)) {
		if (json_tree_node_is_object(entry_node) ||
		    json_tree_node_is_array(entry_node))
		    	continue;

		const char *value_str =	json_tree_node_as_str(entry_node);

		if (str_len(values) > 0)
			str_append_c(values, '\t');
		str_append_tabescaped(values, value_str);
	}
	return str_c(values);
}

static int
get_time_field(const struct json_tree *tree, const char *key,
	       int64_t *value_r)
{
	const struct json_tree_node *value_node = get_field_node(tree, key);

	if (value_node == NULL)
		return 0;

	enum json_type value_type = json_tree_node_get_type(value_node);

	if (value_type == JSON_TYPE_NUMBER) {
		int64_t tstamp;

		if (json_tree_node_get_int64(value_node, &tstamp) < 0 ||
		    tstamp < 0)
			return -1;
		*value_r = tstamp;
		return 1;
	}

	const char *value = json_tree_node_as_str(value_node);
	time_t tvalue;
	int tz_offset ATTR_UNUSED;

	if (iso8601_date_parse((const unsigned char*)value, strlen(value),
			       &tvalue, &tz_offset)) {
		if (tvalue < 0)
			return -1;
		*value_r = tvalue;
		return 1;
	}
	return -1;
}

/* Escapes '/' and '%' in identifier to %hex, and a whole-segment "." or
   ".." to %2e[%2e] */
static const char *escape_identifier(const char *identifier)
{
	/* A bare "." or ".." identifier would form a relative path component
	   in the shared/<azp>/<alg>/<kid> dict key. */
	if (strcmp(identifier, ".") == 0)
		return "%2e";
	if (strcmp(identifier, "..") == 0)
		return "%2e%2e";

	size_t pos = strcspn(identifier, "/%");

	/* nothing to escape */
	if (identifier[pos] == '\0')
		return identifier;

	size_t len = strlen(identifier);
	string_t *new_id = t_str_new(len);

	str_append_data(new_id, identifier, pos);

	for (size_t i = pos; i < len; i++) {
	        switch (identifier[i]) {
	        case '/':
	                str_append(new_id, "%2f");
	                break;
	        case '%':
	                str_append(new_id, "%25");
	                break;
	        default:
	                str_append_c(new_id, identifier[i]);
	                break;
	        }
	}
	return str_c(new_id);
}

static int
oauth2_lookup_hmac_key(const struct oauth2_settings *set, const char *azp,
		       const char *alg, const char *key_id,
		       const buffer_t **hmac_key_r, const char **error_r)
{
	const char *base64_key;
	const char *lookup_key;
	int ret;

	/* Use the same key for the cache and the dict lookup. It must be
	   injective in (azp, alg, key_id): escape_identifier() escapes '/'
	   within each segment, so the slash-joined path cannot collide across
	   different field values. A dot-joined key could collide, since '.' is
	   a valid unescaped character inside the attacker-controlled azp/kid. */
	lookup_key = t_strconcat(DICT_PATH_SHARED, azp, "/", alg, "/", key_id,
				 NULL);
	if (oauth2_validation_key_cache_lookup_hmac_key(
		set->key_cache, lookup_key, hmac_key_r) == 0)
		return 0;

	/* do a synchronous dict lookup */
	struct dict_op_settings dict_set = {
		.username = NULL,
	};
	if ((ret = dict_lookup(set->key_dict, &dict_set, pool_datastack_create(),
			       lookup_key, &base64_key, error_r)) < 0) {
		return -1;
	} else if (ret == 0) {
		*error_r = t_strdup_printf("%s key '%s' not found",
					   str_sanitize_utf8(alg, 32),
					   str_sanitize_utf8(key_id, 128));
		return -1;
	}

	/* decode key */
	buffer_t *key = t_base64_decode_str(base64_key);
	if (key->used == 0) {
		*error_r = "Invalid base64 encoded key";
		return -1;
	}
	oauth2_validation_key_cache_insert_hmac_key(set->key_cache,
						    lookup_key, key);
	*hmac_key_r = key;
	return 0;
}

static int
oauth2_validate_hmac(const struct oauth2_settings *set, const char *azp,
		     const struct oauth2_jwt_alg *alg, const char *key_id,
		     const char *const *blobs, const char **error_r)
{
	const struct hash_method *method = hash_method_lookup(alg->hash);
	const buffer_t *key;

	if (oauth2_lookup_hmac_key(set, azp, alg->name, key_id, &key,
				   error_r) < 0)
		return -1;

	struct hmac_context ctx;
	unsigned char digest[method->digest_size];

	hmac_init(&ctx, key->data, key->used, method);
	hmac_update(&ctx, blobs[0], strlen(blobs[0]));
	hmac_update(&ctx, ".", 1);
	hmac_update(&ctx, blobs[1], strlen(blobs[1]));
	hmac_final(&ctx, digest);

	buffer_t *their_digest =
		t_base64url_decode_str(BASE64_DECODE_FLAG_NO_PADDING, blobs[2]);
	if (method->digest_size != their_digest->used ||
	    !mem_equals_timing_safe(digest, their_digest->data,
				    method->digest_size)) {
		*error_r = "Incorrect JWT signature";
		return -1;
	}
	return 0;
}

static int
oauth2_lookup_pubkey(const struct oauth2_settings *set, const char *azp,
		     const char *alg, const char *key_id,
		     struct dcrypt_public_key **key_r, const char **error_r)
{
	const char *key_str;
	const char *lookup_key;
	int ret;

	/* Use the same key for the cache and the dict lookup; see the comment
	   in oauth2_lookup_hmac_key() about why it must be slash-joined. */
	lookup_key = t_strconcat(DICT_PATH_SHARED, azp, "/", alg, "/", key_id,
				 NULL);
	if (oauth2_validation_key_cache_lookup_pubkey(
		set->key_cache, lookup_key, key_r) == 0)
		return 0;

	/* do a synchronous dict lookup */
	struct dict_op_settings dict_set = {
		.username = NULL,
	};
	if ((ret = dict_lookup(set->key_dict, &dict_set, pool_datastack_create(),
			       lookup_key, &key_str, error_r)) < 0) {
		return -1;
	} else if (ret == 0) {
		*error_r = t_strdup_printf("%s key '%s' not found",
					   str_sanitize_utf8(alg, 32),
					   str_sanitize_utf8(key_id, 128));
		return -1;
	}

	/* try to load key */
	struct dcrypt_public_key *pubkey;
	const char *error;

	if (!dcrypt_key_load_public(&pubkey, key_str, &error)) {
		*error_r = t_strdup_printf("Cannot load key: %s", error);
		return -1;
	}

	/* cache key */
	oauth2_validation_key_cache_insert_pubkey(set->key_cache, lookup_key,
						  pubkey);
	*key_r = pubkey;
	return 0;
}

static int
oauth2_validate_rsa_ecdsa(const struct oauth2_settings *set,
			  const char *azp, const struct oauth2_jwt_alg *alg,
			  const char *key_id, const char *const *blobs,
			  const char **error_r)
{
	enum dcrypt_signature_format sig_format =
		alg->type == OAUTH2_JWT_ALG_EC ? DCRYPT_SIGNATURE_FORMAT_X962 :
		DCRYPT_SIGNATURE_FORMAT_DSS;

	if (!dcrypt_is_initialized()) {
		*error_r = "No crypto library loaded";
		return -1;
	}

	buffer_t *signature =
		t_base64url_decode_str(BASE64_DECODE_FLAG_NO_PADDING, blobs[2]);

	struct dcrypt_public_key *pubkey;
	if (oauth2_lookup_pubkey(set, azp, alg->name, key_id, &pubkey,
				 error_r) < 0)
		return -1;

	/* data to verify */
	const char *data = t_strconcat(blobs[0], ".", blobs[1], NULL);

	/* verify signature */
	bool valid;
	if (!dcrypt_verify(pubkey, alg->hash, sig_format, data, strlen(data),
			   signature->data, signature->used, &valid,
			   alg->padding, error_r)) {
		valid = FALSE;
	} else if (!valid) {
		*error_r = "Bad signature";
	}

	return valid ? 0 : -1;
}

static int
oauth2_validate_signature(const struct oauth2_settings *set, const char *azp,
			  const char *alg_name, const char *key_id,
			  const char *const *blobs, const char **error_r)
{
	const struct oauth2_jwt_alg *alg = oauth2_jwt_alg_find(alg_name);

	if (alg == NULL) {
		*error_r = t_strdup_printf("Unsupported algorithm '%s'",
					   str_sanitize_utf8(alg_name, 32));
		return -1;
	}
	if (alg->type == OAUTH2_JWT_ALG_HMAC)
		return oauth2_validate_hmac(set, azp, alg, key_id, blobs,
					    error_r);
	return oauth2_validate_rsa_ecdsa(set, azp, alg, key_id, blobs,
					 error_r);
}

struct jwt_node {
	const char *prefix;
	const struct json_tree_node *root;
	bool array:1;
};

static void
oauth2_jwt_copy_fields(ARRAY_TYPE(oauth2_field) *fields,
		       struct json_tree *tree)
{
	pool_t pool = array_get_pool(fields);
	ARRAY(struct jwt_node) nodes;

	t_array_init(&nodes, 1);

	struct jwt_node *root = array_append_space(&nodes);

	root->prefix = "";
	root->root = json_tree_get_root_const(tree);

	while (array_count(&nodes) > 0) {
		const struct jwt_node *subroot = array_front(&nodes);
		const struct json_tree_node *tnode = subroot->root;

		while (tnode != NULL) {
			const struct json_node *jnode =
				json_tree_node_get(tnode);

			if (!json_node_is_singular(jnode)) {
				root = array_append_space(&nodes);
				/* array_append_space() may have reallocated the
				   buffer, so refresh subroot to the new location. */
				subroot = array_front(&nodes);
				root->root = json_tree_node_get_child(tnode);
				root->array = json_node_is_array(jnode);
				if (jnode->name == NULL)
					root->prefix = subroot->prefix;
				else if (*subroot->prefix != '\0')
					root->prefix = t_strconcat(subroot->prefix, jnode->name, "_", NULL);
				else
					root->prefix = t_strconcat(jnode->name, "_", NULL);
			} else {
				struct oauth2_field *field = NULL, *field_iter;
				const char *name;

				if (subroot->array) {
					name = strrchr(subroot->prefix, '_');
					if (name != NULL)
						name = t_strdup_until(subroot->prefix, name);
					else
						name = subroot->prefix;
					array_foreach_modifiable(fields, field_iter) {
						if (strcmp(field_iter->name, name) == 0) {
							field = field_iter;
							break;
						}
					}
					if (field == NULL) {
						field = array_append_space(fields);
						field->name = p_strdup(pool, name);
					}
				} else {
					field = array_append_space(fields);
					field->name = p_strconcat(pool, subroot->prefix, jnode->name, NULL);
				}

				const char *value = str_tabescape(json_node_as_str(jnode));

				if (field->value != NULL) {
					field->value = p_strconcat(pool, field->value, "\t", value, NULL);
				} else {
					field->value = p_strdup(pool, value);
				}
			}
			tnode = json_tree_node_get_next(tnode);
		}
		array_pop_front(&nodes);
	}
}

static int
oauth2_jwt_header_process(struct json_tree *tree, const char **alg_r,
			  const char **kid_r, const char **error_r)
{
	const char *alg = get_field(tree, "alg", NULL);
	const char *kid = get_field(tree, "kid", NULL);

	if (alg == NULL) {
		*error_r = "Cannot find 'alg' field";
		return -1;
	}

	/* These are lost when tree is deinitialized.
	   Make sure algorithm is uppercased. */
	*alg_r = t_str_ucase(alg);
	*kid_r = t_strdup(kid);
	return 0;
}

static bool check_scope(const char *req, const char *got)
{
	const char *const *scope_req = t_strsplit_spaces(req, " ,");
	const char *const *scope_got = t_strsplit_spaces(got, " ,");

	for (; *scope_req != NULL; scope_req++)
		if (!str_array_icase_find(scope_got, *scope_req))
			return FALSE;
	return TRUE;
}

static int
oauth2_jwt_body_process(const struct oauth2_settings *set,
			const char *alg, const char *kid,
			ARRAY_TYPE(oauth2_field) *fields,
			struct json_tree *tree,
			const char *const *blobs, const char **error_r)
{
	const char *sub = get_field(tree, "sub", NULL);
	int64_t t0 = time(NULL);
	/* default IAT and NBF to now */
	int64_t iat, nbf, exp;
	int tz_offset ATTR_UNUSED;
	int ret;

	if (sub == NULL) {
		*error_r = "Missing 'sub' field";
		return -1;
	}

	if ((ret = get_time_field(tree, "exp", &exp)) < 1) {
		*error_r = t_strdup_printf("%s 'exp' field",
				ret == 0 ? "Missing" : "Malformed");
		return -1;
	}

	if ((ret = get_time_field(tree, "nbf", &nbf)) < 0) {
		*error_r = "Malformed 'nbf' field";
		return -1;
	} else if (ret == 0 || nbf == 0)
		nbf = t0;

	if ((ret = get_time_field(tree, "iat", &iat)) < 0) {
		*error_r = "Malformed 'iat' field";
		return -1;
	} else if (ret == 0 || iat == 0)
		iat = t0;

	/* Token could have been just generated with a server where time is
	   slightly newer than this server's time. Allow 1 second difference
	   to avoid random failures due to token being into future. */
	if (nbf > t0 + 1) {
		*error_r = t_strdup_printf(
			"Token is not valid yet (nbf=%"PRId64" > %"PRId64")",
			nbf, t0 + 1);
		return -1;
	}
	if (iat > t0 + 1) {
		*error_r = t_strdup_printf(
			"Token is issued in future (iat=%"PRId64" > %"PRId64")",
			iat, t0 + 1);
		return -1;
	}
	/* Allow using slightly expired token, in case client time isn't well
	   synced. */
	if (exp < t0 - set->token_expire_grace_secs) {
		*error_r = t_strdup_printf(
			"Token has expired (exp=%"PRId64" < %"PRId64" - grace %u)",
			exp, t0, set->token_expire_grace_secs);
		return -1;
	}

	/* ensure token dates are not conflicting */
	if (exp < iat ||
	    exp < nbf) {
		*error_r = "Token time values are conflicting";
		return -1;
	}

	const char *iss = get_field(tree, "iss", NULL);

	if (set->issuers != NULL && *set->issuers != NULL) {
		if (iss == NULL) {
			*error_r = "Token is missing 'iss' field";
			return -1;
		}
		if (!str_array_find(set->issuers, iss)) {
			*error_r = t_strdup_printf("Issuer '%s' is not allowed",
						   str_sanitize_utf8(iss, 128));
			return -1;
		}
	}

	const char *aud = get_field_multiple(tree, "aud");

	/* if there is client_id configured, then aud should be present */
	if (set->client_id != NULL && *set->client_id != '\0') {
		if (aud == NULL) {
			*error_r = "client_id set but aud is missing";
			return -1;

		}
		const char *const *auds = t_strsplit_tabescaped(aud);
		if (!str_array_find(auds, set->client_id)) {
			*error_r = "client_id not found in aud field";
			return -1;
		}
	}

	const char *got_scope = get_field(tree, "scope", NULL);
	const char *req_scope = set->scope;

	if (req_scope != NULL && *req_scope != '\0') {
		if (got_scope == NULL) {
			*error_r = "scope set but not found in token";
			return -1;
		}

		if (!check_scope(req_scope, got_scope)) {
			*error_r = t_strdup_printf(
				"configured scope '%s' missing from token scope '%s'",
				req_scope, str_sanitize_utf8(got_scope, 128));
			return -1;
		}
	}

	/* see if there is azp */
	const char *azp = get_field(tree, "azp", NULL);
	if (azp == NULL)
		azp = "default";
	else if (abnf_contains_ascii_ctrl(azp)) {
		*error_r = "'azp' field contains control characters";
		return -1;
	} else
		azp = escape_identifier(azp);

	if (oauth2_validate_signature(set, azp, alg, kid, blobs, error_r) < 0)
		return -1;

	oauth2_jwt_copy_fields(fields, tree);
	return 0;
}

int oauth2_try_parse_jwt(const struct oauth2_settings *set,
			 const char *token, ARRAY_TYPE(oauth2_field) *fields,
			 bool *is_jwt_r, const char **error_r)
{
	const char *const *blobs = t_strsplit(token, ".");
	int ret;

	i_assert(set->key_dict != NULL);

	/* we don't know if it's JWT token yet */
	*is_jwt_r = FALSE;

	if (str_array_length(blobs) != 3) {
		*error_r = "Not a JWT token";
		return -1;
	}

	/* attempt to decode header */
	buffer_t *header =
		t_base64url_decode_str(BASE64_DECODE_FLAG_NO_PADDING, blobs[0]);

	if (header->used == 0) {
		*error_r = "Not a JWT token";
		return -1;
	}

	struct json_tree *header_tree;
	if (oauth2_json_tree_build(header, &header_tree, error_r) < 0)
		return -1;

	const char *alg, *kid;
	ret = oauth2_jwt_header_process(header_tree, &alg, &kid, error_r);
	json_tree_unref(&header_tree);
	if (ret < 0)
		return -1;

	/* it is now assumed to be a JWT token */
	*is_jwt_r = TRUE;

	/* 'kid' and 'azp' are attacker-controlled and end up both in the
	   shared/<azp>/<alg>/<kid> dict key and in error messages written to
	   the authentication log, where a LF would forge extra log lines.
	   Control characters have no legitimate use in either field. */
	if (kid == NULL)
		kid = "default";
	else if (*kid == '\0') {
		*error_r = "'kid' field is empty";
		return -1;
	} else if (abnf_contains_ascii_ctrl(kid)) {
		*error_r = "'kid' field contains control characters";
		return -1;
	} else {
		kid = escape_identifier(kid);
	}

	/* Parse body.

	   NOTE: The body is parsed and its claims are validated before the
	   signature is verified, i.e. an unauthenticated attacker can reach
	   the JSON parser and the claim helpers with unsigned input. This is
	   inherent to JWT as used here: the 'azp' claim needed to select the
	   verification key lives in the body, so the body has to be parsed
	   first. The signature check in oauth2_jwt_body_process() remains the
	   only gate that grants access - nothing here is trusted before it
	   passes. lib-json is fuzzed (see src/lib-json/fuzz-json-istream.c)
	   for this reason. */
	struct json_tree *body_tree;
	buffer_t *body =
		t_base64url_decode_str(BASE64_DECODE_FLAG_NO_PADDING, blobs[1]);
	if (body->used == 0) {
		*error_r = "Not a JWT token";
		return -1;
	}
	if (oauth2_json_tree_build(body, &body_tree, error_r) == -1)
		return -1;
	ret = oauth2_jwt_body_process(set, alg, kid, fields, body_tree, blobs,
				      error_r);
	json_tree_unref(&body_tree);

	return ret;
}

/* The curve's short name, such as "secp224r1". The OID came from OpenSSL,
   so it has a name. The OID is returned only if OpenSSL itself fails. */
static const char *oauth2_jwt_curve_name(const char *curve_oid)
{
	buffer_t *der = t_buffer_create(16);
	const char *name, *error;

	if (!dcrypt_name2oid(curve_oid, der, &error))
		return curve_oid;
	name = dcrypt_oid2name(der->data, der->used, &error);
	return name == NULL ? curve_oid : name;
}

static int
oauth2_jwt_key_alg(struct dcrypt_private_key *key, const char *alg_name,
		   const struct oauth2_jwt_alg **alg_r, const char **error_r)
{
	struct dcrypt_public_key *pubkey;
	enum dcrypt_key_type key_type;
	const char *curve;
	int ret;

	dcrypt_key_convert_private_to_public(key, &pubkey);
	ret = oauth2_jwt_key_type(pubkey, &key_type, &curve, error_r);
	dcrypt_key_unref_public(&pubkey);
	if (ret < 0)
		return -1;

	if (alg_name != NULL) {
		const struct oauth2_jwt_alg *alg = oauth2_jwt_alg_find(alg_name);

		if (alg == NULL || alg->type == OAUTH2_JWT_ALG_HMAC) {
			*error_r = t_strdup_printf("Unsupported algorithm '%s'",
						   alg_name);
			return -1;
		}
		if (!oauth2_jwt_alg_fits_key(alg, key_type, curve)) {
			*error_r = t_strdup_printf(
				"Algorithm '%s' does not match the key",
				alg_name);
			return -1;
		}
		*alg_r = alg;
		return 0;
	}

	/* The first match is RS256 for RSA, or the curve's ES* for EC */
	for (unsigned int i = 0; i < N_ELEMENTS(oauth2_jwt_algs); i++) {
		if (oauth2_jwt_alg_fits_key(&oauth2_jwt_algs[i], key_type,
					    curve)) {
			*alg_r = &oauth2_jwt_algs[i];
			return 0;
		}
	}
	*error_r = t_strdup_printf("No algorithm for EC curve %s",
				   oauth2_jwt_curve_name(curve));
	return -1;
}

int oauth2_jwt_sign(struct dcrypt_private_key *key, const char *alg_name,
		    const char *kid, const struct json_tree *claims,
		    string_t *dest, const char **error_r)
{
	const struct oauth2_jwt_alg *alg;

	if (oauth2_jwt_key_alg(key, alg_name, &alg, error_r) < 0)
		return -1;

	string_t *json = t_str_new(256);
	struct json_ostream *joutput = json_ostream_create_str(json, 0);

	json_ostream_ndescend_object(joutput, NULL);
	json_ostream_nwrite_string(joutput, "typ", "JWT");
	json_ostream_nwrite_string(joutput, "alg", alg->name);
	if (kid != NULL)
		json_ostream_nwrite_string(joutput, "kid", kid);
	json_ostream_nascend_object(joutput);
	json_ostream_nfinish_destroy(&joutput);

	size_t start = str_len(dest);

	base64url_encode(BASE64_ENCODE_FLAG_NO_PADDING, SIZE_MAX,
			 str_data(json), str_len(json), dest);
	str_append_c(dest, '.');
	str_truncate(json, 0);
	json_tree_write_buffer(claims, json, 0, NULL);
	base64url_encode(BASE64_ENCODE_FLAG_NO_PADDING, SIZE_MAX,
			 str_data(json), str_len(json), dest);

	/* JWS wants ECDSA signatures as r || s, each zero-padded to the
	   curve's width (RFC 7518 3.4). dcrypt's X9.62 format pads them. */
	enum dcrypt_signature_format sig_format =
		alg->type == OAUTH2_JWT_ALG_EC ? DCRYPT_SIGNATURE_FORMAT_X962 :
		DCRYPT_SIGNATURE_FORMAT_DSS;
	buffer_t *sig = t_buffer_create(256);

	if (!dcrypt_sign(key, alg->hash, sig_format, str_data(dest) + start,
			 str_len(dest) - start, sig, alg->padding, error_r)) {
		str_truncate(dest, start);
		return -1;
	}
	str_append_c(dest, '.');
	base64url_encode(BASE64_ENCODE_FLAG_NO_PADDING, SIZE_MAX,
			 sig->data, sig->used, dest);
	return 0;
}
