/* Copyright (c) 2026 Dovecot authors, see the included COPYING file */

#include "test-auth.h"
#include "auth-common.h"
#include "auth-request.h"
#include "auth-settings.h"
#include "db-oauth2.h"
#include "passdb.h"
#include "hmac.h"
#include "sha2.h"
#include "base64.h"
#include "randgen.h"
#include "str.h"
#include "settings.h"
#include "dict.h"
#include "dict-private.h"

extern const struct setting_parser_info fs_setting_parser_info;
#include "mkdir-parents.h"
#include "unlink-directory.h"
#include "write-full.h"
#include "test-dir.h"

#include <fcntl.h>
#include <time.h>

static struct settings_simple oauth2_local_set;
static char *test_key_dir = NULL;
static buffer_t *test_hmac_key = NULL;

static void write_key_file(const char *path, const buffer_t *key)
{
	const char *dir = t_strdup_until(path, strrchr(path, '/'));
	if (mkdir_parents(dir, 0700) < 0 && errno != EEXIST)
		i_fatal("mkdir_parents(%s) failed: %m", dir);

	buffer_t *b64 = t_base64_encode(0, SIZE_MAX, key->data, key->used);
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
		i_fatal("open(%s) failed: %m", path);
	if (write_full(fd, b64->data, b64->used) < 0)
		i_fatal("write(%s) failed: %m", path);
	i_close_fd(&fd);
}

static void init_local_db(const char *const *extra_settings,
			   struct db_oauth2 **db_r)
{
	const char *error;

	test_key_dir = i_strdup_printf("%s/oauth2-keys", test_dir_get());
	if (mkdir(test_key_dir, 0700) < 0 && errno != EEXIST)
		i_fatal("mkdir(%s) failed: %m", test_key_dir);

	/* generate HMAC key */
	test_hmac_key = buffer_create_dynamic(default_pool, 32);
	void *ptr = buffer_append_space_unsafe(test_hmac_key, 32);
	random_fill(ptr, 32);

	/* key file path: <dir>/default/HS256/default
	   (fs-dict maps shared/default/HS256/default → default/HS256/default) */
	write_key_file(t_strdup_printf("%s/default/HS256/default", test_key_dir),
		       test_hmac_key);

	/* build settings array with base + any extra */
	const char *const base_settings[] = {
		"oauth2_introspection_mode", "local",
		"oauth2_username_attribute", "email",
		"oauth2_token_expire_grace", "0",
		"dict", "fs",
		"dict/fs/dict_driver", "fs",
		"fs", "posix",
		"fs/posix/fs_driver", "posix",
		"fs_posix_prefix", t_strdup_printf("%s/", test_key_dir),
		NULL
	};

	/* count and merge settings arrays */
	unsigned int base_count = str_array_length(base_settings);
	unsigned int extra_count = extra_settings != NULL ?
		str_array_length(extra_settings) : 0;
	const char **all = t_new(const char *, base_count + extra_count + 1);
	memcpy(all, base_settings, base_count * sizeof(*all));
	if (extra_settings != NULL)
		memcpy(all + base_count, extra_settings,
		       extra_count * sizeof(*all));
	all[base_count + extra_count] = NULL;

	dict_drivers_register_builtin();
	settings_info_register(&dict_setting_parser_info);
	settings_info_register(&fs_setting_parser_info);
	settings_simple_init(&oauth2_local_set, all);

	if (db_oauth2_init(oauth2_local_set.event, FALSE, db_r, &error) < 0)
		i_fatal("db_oauth2_init: %s", error);
}

static void deinit_local_db(void)
{
	const char *error;

	db_oauth2_deinit();
	dict_drivers_unregister_builtin();
	settings_simple_deinit(&oauth2_local_set);

	if (unlink_directory(test_key_dir, UNLINK_DIRECTORY_FLAG_RMDIR,
			     &error) < 0)
		i_error("unlink_directory(%s): %s", test_key_dir, error);
	i_free(test_key_dir);
	buffer_free(&test_hmac_key);
}

static const char *
build_jwt(time_t exp, const char *email, const char *scope, const char *aud,
	  bool bad_sig)
{
	const char *hdr = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
	buffer_t *tokenbuf = t_buffer_create(256);

	base64url_encode(BASE64_ENCODE_FLAG_NO_PADDING, SIZE_MAX,
			 (const unsigned char *)hdr, strlen(hdr), tokenbuf);
	buffer_append(tokenbuf, ".", 1);

	string_t *body = t_str_new(128);
	str_printfa(body,
		    "{\"sub\":\"%s\",\"email\":\"%s\","
		    "\"exp\":%"PRIdTIME_T",\"iat\":%"PRIdTIME_T,
		    email, email, exp, (time_t)(exp - 3600));
	if (scope != NULL)
		str_printfa(body, ",\"scope\":\"%s\"", scope);
	if (aud != NULL) {
		const char *const *auds = t_strsplit_spaces(aud, " ");
		if (auds[0] != NULL && auds[1] != NULL) {
			str_append(body, ",\"aud\":[");
			for (unsigned int i = 0; auds[i] != NULL; i++) {
				if (i > 0)
					str_append_c(body, ',');
				str_printfa(body, "\"%s\"", auds[i]);
			}
			str_append_c(body, ']');
		} else {
			str_printfa(body, ",\"aud\":\"%s\"", aud);
		}
	}
	str_append_c(body, '}');

	base64url_encode(BASE64_ENCODE_FLAG_NO_PADDING, SIZE_MAX,
			 str_data(body), str_len(body),
			 tokenbuf);

	buffer_t *sig = t_hmac_buffer(&hash_method_sha256,
				       test_hmac_key->data, test_hmac_key->used,
				       tokenbuf);
	if (bad_sig) {
		unsigned char *p = buffer_get_space_unsafe(sig, sig->used - 1, 1);
		*p ^= 0xff;
	}

	buffer_append(tokenbuf, ".", 1);
	base64url_encode(BASE64_ENCODE_FLAG_NO_PADDING, SIZE_MAX,
			 sig->data, sig->used, tokenbuf);

	return str_c(tokenbuf);
}

struct test_cb_ctx {
	enum passdb_result result;
	bool done;
};

static void
test_lookup_cb(struct db_oauth2_request *req ATTR_UNUSED,
	       enum passdb_result result,
	       const char *error ATTR_UNUSED,
	       struct test_cb_ctx *ctx)
{
	ctx->result = result;
	ctx->done = TRUE;
}

static enum passdb_result
run_lookup(struct db_oauth2 *db, const char *user, const char *token)
{
	pool_t pool = pool_alloconly_create("test-oauth2-req", 4096);

	struct db_oauth2_request *req = p_new(pool, struct db_oauth2_request, 1);
	req->pool = pool;

	/* Create a minimal auth_request without going through auth_request_new
	   since global_auth_settings is not initialized in this test binary. */
	struct auth_request *ar = p_new(pool, struct auth_request, 1);
	ar->pool = pool;
	ar->refcount = 1;
	ar->event = event_create(auth_event);
	event_add_category(ar->event, &event_category_auth);
	ar->fields.extra_fields = auth_fields_init(pool);
	p_array_init(&ar->authdb_event, pool, 2);
	ar->fields.user = p_strdup(pool, user);

	struct test_cb_ctx ctx = { .done = FALSE };
	db_oauth2_lookup(db, req, token, ar, test_lookup_cb, &ctx);
	i_assert(ctx.done);

	event_unref(&ar->event);
	pool_unref(&pool);
	return ctx.result;
}

void test_db_oauth2(void)
{
	struct db_oauth2 *db;
	const char *token;
	time_t now = time(NULL);

	test_dir_init("test-db-oauth2");

	test_begin("db-oauth2: local validation - valid token");
	init_local_db(NULL, &db);
	token = build_jwt(now + 3600, "user@example.com", NULL, NULL, FALSE);
	test_assert(run_lookup(db, "user@example.com", token) == PASSDB_RESULT_OK);
	deinit_local_db();
	test_end();

	test_begin("db-oauth2: local validation - expired token");
	init_local_db(NULL, &db);
	token = build_jwt(now - 7200, "user@example.com", NULL, NULL, FALSE);
	test_assert(run_lookup(db, "user@example.com", token) ==
		    PASSDB_RESULT_PASSWORD_MISMATCH);
	deinit_local_db();
	test_end();

	test_begin("db-oauth2: local validation - wrong username");
	init_local_db(NULL, &db);
	token = build_jwt(now + 3600, "other@example.com", NULL, NULL, FALSE);
	test_assert(run_lookup(db, "user@example.com", token) ==
		    PASSDB_RESULT_USER_UNKNOWN);
	deinit_local_db();
	test_end();

	test_begin("db-oauth2: local validation - bad signature");
	init_local_db(NULL, &db);
	token = build_jwt(now + 3600, "user@example.com", NULL, NULL, TRUE);
	test_assert(run_lookup(db, "user@example.com", token) ==
		    PASSDB_RESULT_PASSWORD_MISMATCH);
	deinit_local_db();
	test_end();

	test_begin("db-oauth2: local validation - required scope present");
	const char *const scope_req_present[] = { "oauth2_scope", "email", NULL };
	init_local_db(scope_req_present, &db);
	token = build_jwt(now + 3600, "user@example.com",
			  "email profile", NULL, FALSE);
	test_assert(run_lookup(db, "user@example.com", token) ==
		    PASSDB_RESULT_OK);
	deinit_local_db();
	test_end();

	test_begin("db-oauth2: local validation - required scope missing");
	const char *const scope_req_missing[] = { "oauth2_scope", "admin", NULL };
	init_local_db(scope_req_missing, &db);
	token = build_jwt(now + 3600, "user@example.com",
			  "email profile", NULL, FALSE);
	/* JWT-level scope check fails first */
	test_assert(run_lookup(db, "user@example.com", token) ==
		    PASSDB_RESULT_PASSWORD_MISMATCH);
	deinit_local_db();
	test_end();

	test_begin("db-oauth2: local validation - required audience present");
	const char *const aud_req_present[] = { "oauth2_audience", "dovecot", NULL };
	init_local_db(aud_req_present, &db);
	token = build_jwt(now + 3600, "user@example.com", NULL,
			  "dovecot", FALSE);
	test_assert(run_lookup(db, "user@example.com", token) ==
		    PASSDB_RESULT_OK);
	deinit_local_db();
	test_end();

	test_begin("db-oauth2: local validation - required audience missing");
	const char *const aud_req_missing[] = { "oauth2_audience", "dovecot", NULL };
	init_local_db(aud_req_missing, &db);
	token = build_jwt(now + 3600, "user@example.com", NULL,
			  "other", FALSE);
	test_assert(run_lookup(db, "user@example.com", token) ==
		    PASSDB_RESULT_USER_DISABLED);
	deinit_local_db();
	test_end();

	test_begin("db-oauth2: local validation - multiple required scopes all present");
	const char *const scope_multi_present[] = {
		"oauth2_scope", "email",
		"oauth2_scope", "profile",
		NULL
	};
	init_local_db(scope_multi_present, &db);
	token = build_jwt(now + 3600, "user@example.com",
			  "email profile openid", NULL, FALSE);
	test_assert(run_lookup(db, "user@example.com", token) ==
		    PASSDB_RESULT_OK);
	deinit_local_db();
	test_end();

	test_begin("db-oauth2: local validation - multiple required scopes one missing");
	const char *const scope_multi_missing[] = {
		"oauth2_scope", "email",
		"oauth2_scope", "admin",
		NULL
	};
	init_local_db(scope_multi_missing, &db);
	token = build_jwt(now + 3600, "user@example.com",
			  "email profile", NULL, FALSE);
	/* JWT-level scope check fails first */
	test_assert(run_lookup(db, "user@example.com", token) ==
		    PASSDB_RESULT_PASSWORD_MISMATCH);
	deinit_local_db();
	test_end();

	test_begin("db-oauth2: local validation - multiple required audiences all present");
	const char *const aud_multi_present[] = {
		"oauth2_audience", "dovecot",
		"oauth2_audience", "imap",
		NULL
	};
	init_local_db(aud_multi_present, &db);
	token = build_jwt(now + 3600, "user@example.com", NULL,
			  "dovecot imap", FALSE);
	test_assert(run_lookup(db, "user@example.com", token) ==
		    PASSDB_RESULT_OK);
	deinit_local_db();
	test_end();

	test_begin("db-oauth2: local validation - multiple required audiences one missing");
	const char *const aud_multi_missing[] = {
		"oauth2_audience", "dovecot",
		"oauth2_audience", "admin",
		NULL
	};
	init_local_db(aud_multi_missing, &db);
	token = build_jwt(now + 3600, "user@example.com", NULL,
			  "dovecot imap", FALSE);
	test_assert(run_lookup(db, "user@example.com", token) ==
		    PASSDB_RESULT_USER_DISABLED);
	deinit_local_db();
	test_end();
}
