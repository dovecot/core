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
#include "ioloop.h"
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

#define OAUTH2_SETTINGS_ERROR_PREFIX \
	"auth_oauth2 settings: Invalid settings: "

struct oauth2_url_check_case {
	const char *name;
	const char *const *settings;
	bool expect_success;
	const char *error;
};

void test_db_oauth2_url_check(void)
{
	const struct oauth2_url_check_case cases[] = {
		{
			"tokeninfo_url without %{access_token} is rejected",
			(const char *const[]) {
				"oauth2_introspection_mode", "post",
				"oauth2_tokeninfo_url", "http://h/?access_token=",
				NULL
			},
			FALSE,
			"oauth2_tokeninfo_url must contain %{access_token}",
		},
		{
			"tokeninfo_url with %{access_token} is accepted",
			(const char *const[]) {
				"oauth2_introspection_mode", "post",
				"oauth2_tokeninfo_url",
				"http://h/?access_token=%{access_token}",
				NULL
			},
			TRUE, NULL,
		},
		{
			"introspection_url without %{access_token} is "
			"rejected with mode=get",
			(const char *const[]) {
				"oauth2_introspection_mode", "get",
				"oauth2_introspection_url", "http://h/i",
				NULL
			},
			FALSE,
			"oauth2_introspection_url must contain %{access_token}",
		},
		{
			"introspection_url with %{access_token} is rejected "
			"with mode=post",
			(const char *const[]) {
				"oauth2_introspection_mode", "post",
				"oauth2_introspection_url",
				"http://h/i?t=%{access_token}",
				NULL
			},
			FALSE,
			"oauth2_introspection_url can't contain %{access_token} with "
			"oauth2_introspection_mode=post",
		},
		{
			"%{access_token} in the host is rejected",
			(const char *const[]) {
				"oauth2_introspection_mode", "auth",
				"oauth2_tokeninfo_url",
				"http://%{access_token}.h/",
				NULL
			},
			FALSE,
			"oauth2_tokeninfo_url: "
			"%{access_token} must be in the URL path or query",
		},
		{
			"an unsupported variable is rejected",
			(const char *const[]) {
				"oauth2_introspection_mode", "post",
				"oauth2_tokeninfo_url",
				"http://h/?t=%{access_token}&u=%{user}",
				NULL
			},
			FALSE,
			"oauth2_tokeninfo_url: Unsupported variable %{user}",
		},
		{
			"%{access_token} in the userinfo is rejected",
			(const char *const[]) {
				"oauth2_introspection_mode", "auth",
				"oauth2_tokeninfo_url",
				"http://u:%{access_token}@h/",
				NULL
			},
			FALSE,
			"oauth2_tokeninfo_url: "
			"%{access_token} must be in the URL path or query",
		},
		{
			"%{access_token} in the port is rejected",
			(const char *const[]) {
				"oauth2_introspection_mode", "auth",
				"oauth2_tokeninfo_url",
				"http://h:%{access_token}/",
				NULL
			},
			FALSE,
			"oauth2_tokeninfo_url: "
			"%{access_token} must be in the URL path or query",
		},
		{
			"%{access_token} after a variable's // is rejected",
			(const char *const[]) {
				"oauth2_introspection_mode", "auth",
				"oauth2_tokeninfo_url",
				"%{env:OAUTH2_UNUSED|safe}//%{access_token}/",
				NULL
			},
			FALSE,
			"oauth2_tokeninfo_url: "
			"%{access_token} must be in the URL path or query",
		},
		{
			"%{access_token} appended to a variable is rejected",
			(const char *const[]) {
				"oauth2_introspection_mode", "auth",
				"oauth2_tokeninfo_url",
				"%{env:OAUTH2_UNUSED|safe}%{access_token}",
				NULL
			},
			FALSE,
			"oauth2_tokeninfo_url: "
			"%{access_token} must be in the URL path or query",
		},
		{
			"a base URL variable is accepted without being set",
			(const char *const[]) {
				"oauth2_introspection_mode", "auth",
				"oauth2_tokeninfo_url",
				"%{env:OAUTH2_UNUSED|safe}/tokeninfo?"
				"t=%{access_token}",
				NULL
			},
			TRUE, NULL,
		},
		{
			"a port variable is accepted without being set",
			(const char *const[]) {
				"oauth2_introspection_mode", "auth",
				"oauth2_tokeninfo_url",
				"http://h:%{env:OAUTH2_UNUSED|safe}/tokeninfo?"
				"t=%{access_token}",
				NULL
			},
			TRUE, NULL,
		},
		{
			"userinfo variables are accepted without safe",
			(const char *const[]) {
				"oauth2_introspection_mode", "auth",
				"oauth2_tokeninfo_url",
				"http://%{env:OAUTH2_UNUSED}:%{env:OAUTH2_UNUSED2}"
				"@h/?t=%{access_token}",
				NULL
			},
			TRUE, NULL,
		},
		{
			"a base URL variable without safe is rejected",
			(const char *const[]) {
				"oauth2_introspection_mode", "auth",
				"oauth2_tokeninfo_url",
				"%{env:OAUTH2_UNUSED}/tokeninfo?t=%{access_token}",
				NULL
			},
			FALSE,
			"oauth2_tokeninfo_url: %{env:OAUTH2_UNUSED} is part of "
			"the URL scheme or host and needs the safe filter, "
			"use %{env:OAUTH2_UNUSED|safe}",
		},
		{
			"a port variable without safe is rejected",
			(const char *const[]) {
				"oauth2_introspection_mode", "auth",
				"oauth2_tokeninfo_url",
				"http://h:%{env:OAUTH2_UNUSED}/tokeninfo?"
				"t=%{access_token}",
				NULL
			},
			FALSE,
			"oauth2_tokeninfo_url: %{env:OAUTH2_UNUSED} is part of "
			"the URL scheme or host and needs the safe filter, "
			"use %{env:OAUTH2_UNUSED|safe}",
		},
		{
			"a URL without a scheme is rejected",
			(const char *const[]) {
				"oauth2_introspection_mode", "auth",
				"oauth2_tokeninfo_url",
				"htp//h/?t=%{access_token}",
				NULL
			},
			FALSE,
			"Invalid oauth2_tokeninfo_url: Relative HTTP URL not allowed",
		},
		{
			"a syntax error is rejected",
			(const char *const[]) {
				"oauth2_introspection_mode", "post",
				"oauth2_tokeninfo_url",
				"http://h/?t=%{access_token",
				NULL
			},
			FALSE,
			"Invalid oauth2_tokeninfo_url: syntax error, unexpected end of "
			"file, expecting CCBRACE or PIPE",
		},
		{
			"userinfo in introspection_url is still accepted",
			(const char *const[]) {
				"oauth2_introspection_mode", "post",
				"oauth2_introspection_url",
				"http://id:secret@h/i",
				NULL
			},
			TRUE, NULL,
		},
		{
			"a filter on %{access_token} doesn't hide the "
			"variable from the check",
			(const char *const[]) {
				"oauth2_introspection_mode", "get",
				"oauth2_introspection_url",
				"http://h/i?t=%{access_token | lower}",
				NULL
			},
			TRUE, NULL,
		},
	};

	for (unsigned int i = 0; i < N_ELEMENTS(cases); i++) {
		const struct oauth2_url_check_case *c = &cases[i];
		struct settings_simple set;
		const struct auth_oauth2_settings *oset;
		const char *error;

		test_begin(t_strdup_printf("db-oauth2: %s", c->name));

		settings_simple_init(&set, c->settings);
		int ret = settings_get(set.event, &auth_oauth2_setting_parser_info,
				       0, &oset, &error);
		if (c->expect_success) {
			test_assert_idx(ret == 0, i);
			if (ret < 0)
				i_error("%s", error);
			else
				settings_free(oset);
		} else {
			test_assert_idx(ret < 0, i);
			if (ret < 0) {
				test_assert_strcmp_idx(error, t_strconcat(
					OAUTH2_SETTINGS_ERROR_PREFIX, c->error,
					NULL), i);
			} else {
				settings_free(oset);
			}
		}
		settings_simple_deinit(&set);

		test_end();
	}
}

static void
test_lookup_cb_stop(struct db_oauth2_request *req, enum passdb_result result,
		    const char *error, struct test_cb_ctx *ctx)
{
	test_lookup_cb(req, result, error, ctx);
	io_loop_stop(current_ioloop);
}

void test_db_oauth2_grant_url_unset(void)
{
	const char *const settings[] = {
		"oauth2_introspection_mode", "auth",
		"oauth2_tokeninfo_url",
		"http://127.0.0.1:1/?access_token=%{access_token}",
		NULL
	};
	struct settings_simple set;
	struct db_oauth2 *db;
	const char *error = NULL;

	test_begin("db-oauth2: grant password with unset grant_url fails the request");

	settings_simple_init(&set, settings);
	if (db_oauth2_init(set.event, TRUE, &db, &error) < 0)
		test_failed(error);
	else {
		/* oauth2_passwd_grant_start() must fail the request instead
		   of passing the unset (all-zero) grant_url into
		   http_client_request_url(), which asserts on its NULL host
		   name. */
		pool_t pool = pool_alloconly_create("test-oauth2-req", 4096);
		struct db_oauth2_request *req =
			p_new(pool, struct db_oauth2_request, 1);
		req->pool = pool;

		struct auth_request *ar = p_new(pool, struct auth_request, 1);
		ar->pool = pool;
		ar->refcount = 1;
		ar->event = event_create(auth_event);
		event_add_category(ar->event, &event_category_auth);
		/* Debug logging must not stringify the unset grant_url. */
		event_set_forced_debug(ar->event, TRUE);
		ar->fields.extra_fields = auth_fields_init(pool);
		p_array_init(&ar->authdb_event, pool, 2);
		ar->fields.user = p_strdup(pool, "user");
		ar->mech_password = p_strdup(pool, "pass");

		struct test_cb_ctx ctx = { .done = FALSE };
		db_oauth2_lookup(db, req, "pass", ar, test_lookup_cb_stop, &ctx);
		/* The failure is reported from a zero timeout. */
		if (!ctx.done)
			io_loop_run(current_ioloop);
		test_assert(ctx.done);
		test_assert(ctx.result == PASSDB_RESULT_INTERNAL_FAILURE);

		event_unref(&ar->event);
		pool_unref(&pool);
		db_oauth2_deinit();
	}
	settings_simple_deinit(&set);

	test_end();
}

void test_db_oauth2_url_check_no_expand(void)
{
	/* %{env:OAUTH2_UNUSED} makes the template have a variable other
	   than access_token; SETTINGS_EVENT_NO_EXPAND simulates a plain
	   "doveconf -n" settings dump. The %{access_token} host placement
	   must still be rejected here, not only with -x/-F. */
	const char *const settings[] = {
		"oauth2_introspection_mode", "auth",
		"oauth2_tokeninfo_url",
		"http://%{access_token}@h/?x=%{env:OAUTH2_UNUSED}",
		NULL
	};
	struct settings_simple set;
	const struct auth_oauth2_settings *oset;
	const char *error;

	test_begin("db-oauth2: %{access_token} in host is rejected under "
		  "SETTINGS_EVENT_NO_EXPAND");

	settings_simple_init(&set, settings);
	event_add_str(set.event, SETTINGS_EVENT_NO_EXPAND, "yes");
	int ret = settings_get(set.event, &auth_oauth2_setting_parser_info,
			       0, &oset, &error);
	test_assert(ret < 0);
	if (ret < 0) {
		test_assert_strcmp(error, OAUTH2_SETTINGS_ERROR_PREFIX
			"oauth2_tokeninfo_url: %{access_token} must be in "
			"the URL path or query");
	} else {
		settings_free(oset);
	}
	settings_simple_deinit(&set);

	test_end();
}
