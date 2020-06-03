/* Copyright (c) 2020 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "str.h"
#include "hmac.h"
#include "array.h"
#include "hash-method.h"
#include "istream.h"
#include "iso8601-date.h"
#include "json-tree.h"
#include "array.h"
#include "base64.h"
#include "str-sanitize.h"
#include "dcrypt.h"
#include "var-expand.h"
#include "oauth2.h"
#include "oauth2-private.h"
#include "dict.h"

#include <time.h>

static const char *get_field(const struct json_tree *tree, const char *key)
{
	const struct json_tree_node *root = json_tree_root(tree);
	const struct json_tree_node *value_node = json_tree_find_key(root, key);
	if (value_node == NULL || value_node->value_type == JSON_TYPE_OBJECT ||
	    value_node->value_type == JSON_TYPE_ARRAY)
		return NULL;
	return json_tree_get_value_str(value_node);
}

static int get_time_field(const struct json_tree *tree, const char *key,
			  long *value_r)
{
	const char *value = get_field(tree, key);
	int tz_offset ATTR_UNUSED;
	if (value == NULL)
		return 0;
	if ((str_to_long(value, value_r) < 0 &&
	     !iso8601_date_parse((const unsigned char*)value, strlen(value),
				 value_r, &tz_offset)) ||
	    *value_r < 0)
		 return -1;
	return 1;
}

static int oauth2_lookup_hmac_key(const struct oauth2_settings *set,
				  const char *azp, const char *alg, const char *key_id,
				  const buffer_t **hmac_key_r,
				  const char **error_r)
{
	const char *base64_key;
	const char *cache_key_id = t_strconcat(azp, ".", alg, ".", key_id, NULL);
	if (oauth2_validation_key_cache_lookup_hmac_key(set->key_cache, cache_key_id,
							hmac_key_r) == 0)
		return 0;
	int ret;
	const char *lookup_key = t_strconcat(DICT_PATH_SHARED, azp, "/", alg, "/", key_id, NULL);
	/* do a synchronous dict lookup */
	if ((ret = dict_lookup(set->key_dict, pool_datastack_create(),
			       lookup_key, &base64_key, error_r)) < 0) {
		return -1;
	} else if (ret == 0) {
		*error_r = t_strdup_printf("%s key '%s' not found", alg, key_id);
		return -1;
	}

	/* decode key */
	buffer_t *key = t_base64_decode_str(base64_key);
	if (key->used == 0) {
		*error_r = "Invalid base64 encoded key";
		return -1;
	}
	oauth2_validation_key_cache_insert_hmac_key(set->key_cache, cache_key_id, key);
	*hmac_key_r = key;
	return 0;
}

static int oauth2_validate_hmac(const struct oauth2_settings *set,
				const char *azp, const char *alg, const char *key_id,
				const char *const *blobs, const char **error_r)
{
	const struct hash_method *method;
	if (strcmp(alg, "HS256") == 0)
		method = hash_method_lookup("sha256");
	else if (strcmp(alg, "HS384") == 0)
		method = hash_method_lookup("sha384");
	else if (strcmp(alg, "HS512") == 0)
		method = hash_method_lookup("sha512");
	else {
		*error_r = t_strdup_printf("unsupported algorithm '%s'", alg);
		return -1;
	}

	const buffer_t *key;
	if (oauth2_lookup_hmac_key(set, azp, alg, key_id, &key, error_r) < 0)
		return -1;
	struct hmac_context ctx;
	hmac_init(&ctx, key->data, key->used, method);
	hmac_update(&ctx, blobs[0], strlen(blobs[0]));
	hmac_update(&ctx, ".", 1);
	hmac_update(&ctx, blobs[1], strlen(blobs[1]));
	unsigned char digest[method->digest_size];

	hmac_final(&ctx, digest);

	buffer_t *their_digest =
		t_base64url_decode_str(BASE64_DECODE_FLAG_NO_PADDING, blobs[2]);
	if (method->digest_size != their_digest->used ||
	    !mem_equals_timing_safe(digest, their_digest->data, method->digest_size)) {
		*error_r = "Incorrect JWT signature";
		return -1;
	}
	return 0;
}

static int oauth2_lookup_pubkey(const struct oauth2_settings *set,
				const char *azp, const char *alg, const char *key_id,
				struct dcrypt_public_key **key_r,
				const char **error_r)
{
	const char *key_str;
	const char *cache_key_id = t_strconcat(azp, ".", alg, ".", key_id, NULL);
	if (oauth2_validation_key_cache_lookup_pubkey(set->key_cache, cache_key_id, key_r) == 0)
		return 0;
	int ret;
	const char *lookup_key = t_strconcat(DICT_PATH_SHARED, azp, "/", alg, "/", key_id, NULL);
	/* do a synchronous dict lookup */
	if ((ret = dict_lookup(set->key_dict, pool_datastack_create(),
			       lookup_key, &key_str, error_r)) < 0) {
		return -1;
	} else if (ret == 0) {
		*error_r = t_strdup_printf("%s key '%s' not found", alg, key_id);
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
	oauth2_validation_key_cache_insert_pubkey(set->key_cache, cache_key_id, pubkey);
	*key_r = pubkey;
	return 0;
}

static int oauth2_validate_rsa_ecdsa(const struct oauth2_settings *set,
				     const char *azp, const char *alg, const char *key_id,
				     const char *const *blobs, const char **error_r)
{
	const char *method;
	enum dcrypt_padding padding;
	enum dcrypt_signature_format sig_format;
	if (!dcrypt_is_initialized()) {
		*error_r = "No crypto library loaded";
		return -1;
	}

	if (str_begins(alg, "RS")) {
		padding = DCRYPT_PADDING_RSA_PKCS1;
		sig_format = DCRYPT_SIGNATURE_FORMAT_DSS;
	} else if (str_begins(alg, "PS")) {
		padding = DCRYPT_PADDING_RSA_PKCS1_PSS;
		sig_format = DCRYPT_SIGNATURE_FORMAT_DSS;
	} else if (str_begins(alg, "ES")) {
		padding = DCRYPT_PADDING_DEFAULT;
		sig_format = DCRYPT_SIGNATURE_FORMAT_X962;
	} else {
		/* this should be checked by caller */
		i_unreached();
	}

	if (strcmp(alg+2, "256") == 0) {
		method = "sha256";
	} else if (strcmp(alg+2, "384") == 0) {
		method = "sha384";
	} else if (strcmp(alg+2, "512") == 0) {
		method = "sha512";
	} else {
		*error_r = t_strdup_printf("Unsupported algorithm '%s'", alg);
		return -1;
	}

	buffer_t *signature =
		t_base64url_decode_str(BASE64_DECODE_FLAG_NO_PADDING, blobs[2]);

	struct dcrypt_public_key *pubkey;
	if (oauth2_lookup_pubkey(set, azp, alg, key_id, &pubkey, error_r) < 0)
		return -1;

	/* data to verify */
	const char *data = t_strconcat(blobs[0], ".", blobs[1], NULL);

	/* verify signature */
	bool valid;
	if (!dcrypt_verify(pubkey, method, sig_format, data, strlen(data),
			   signature->data, signature->used, &valid, padding, error_r)) {
		valid = FALSE;
	} else if (!valid) {
		*error_r = "Bad signature";
	}

	return valid ? 0 : -1;
}

static int oauth2_validate_signature(const struct oauth2_settings *set,
				     const char *azp, const char *alg, const char *key_id,
				     const char *const *blobs, const char **error_r)
{
	if (str_begins(alg, "HS"))
		return oauth2_validate_hmac(set, azp, alg, key_id, blobs, error_r);
	else if (str_begins(alg, "RS") || str_begins(alg, "PS") ||
		 str_begins(alg, "ES"))
		return oauth2_validate_rsa_ecdsa(set, azp, alg, key_id, blobs, error_r);

	*error_r = t_strdup_printf("Unsupported algorithm '%s'", alg);
	return -1;
}

static void
oauth2_jwt_copy_fields(ARRAY_TYPE(oauth2_field) *fields, struct json_tree *tree)
{
	pool_t pool = array_get_pool(fields);
	ARRAY(const struct json_tree_node*) nodes;
	t_array_init(&nodes, 1);
	const struct json_tree_node *root = json_tree_root(tree);
	array_push_back(&nodes, &root);

	while (array_count(&nodes) > 0) {
		const struct json_tree_node *const *pnode = array_front(&nodes);
		const struct json_tree_node *node = *pnode;
		array_pop_front(&nodes);
		while (node != NULL) {
			if (node->value_type == JSON_TYPE_OBJECT) {
				root = node->value.child;
				array_push_back(&nodes, &root);
			} else if (node->key != NULL) {
				struct oauth2_field *field =
					array_append_space(fields);
				field->name = p_strdup(pool, node->key);
				field->value = p_strdup(pool, json_tree_get_value_str(node));
			}
			node = node->next;
		}
	}
}

static int
oauth2_jwt_header_process(struct json_tree *tree, const char **alg_r,
			  const char **kid_r, const char **error_r)
{
	const char *typ = get_field(tree, "typ");
	const char *alg = get_field(tree, "alg");
	const char *kid = get_field(tree, "kid");

	if (null_strcmp(typ, "JWT") != 0) {
		*error_r = "Cannot find 'typ' field";
		return -1;
	}

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

static int
oauth2_jwt_body_process(const struct oauth2_settings *set, const char *alg, const char *kid,
			ARRAY_TYPE(oauth2_field) *fields, struct json_tree *tree,
			const char *const *blobs, const char **error_r)
{
	const char *sub = get_field(tree, "sub");

	int ret;
	long t0 = time(NULL);
	/* default IAT and NBF to now */
	long iat, nbf, exp;
	int tz_offset ATTR_UNUSED;

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

	if (nbf > t0) {
		*error_r = "Token is not valid yet";
		return -1;
	}
	if (iat > t0) {
		*error_r = "Token is issued in future";
		return -1;
	}
	if (exp < t0) {
		*error_r = "Token has expired";
		return -1;
	}

	/* ensure token dates are not conflicting */
	if (nbf < iat ||
	    exp < iat ||
	    exp < nbf) {
		*error_r = "Token time values are conflicting";
		return -1;
	}

	const char *iss = get_field(tree, "iss");
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

	/* see if there is azp */
	const char *azp = get_field(tree, "azp");
	if (azp == NULL)
		azp = "default";

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
	json_tree_deinit(&header_tree);
	if (ret < 0)
		return -1;

	/* it is now assumed to be a JWT token */
	*is_jwt_r = TRUE;

	if (kid == NULL)
		kid = "default";
	else if (*kid == '\0') {
		*error_r = "'kid' field is empty";
		return -1;
	}

	/* parse body */
	struct json_tree *body_tree;
	buffer_t *body =
		t_base64url_decode_str(BASE64_DECODE_FLAG_NO_PADDING, blobs[1]);
	if (oauth2_json_tree_build(body, &body_tree, error_r) == -1)
		return -1;
	ret = oauth2_jwt_body_process(set, alg, kid, fields, body_tree, blobs, error_r);
	json_tree_deinit(&body_tree);

	return ret;
}
