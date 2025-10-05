/* Copyright (c) 2025 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "str-sanitize.h"
#include "strfuncs.h"
#include "base64.h"
#include "hex-binary.h"
#include "ioloop.h"
#include "istream.h"
#include "password-scheme.h"
#include "gssapi-dummy.h"
#include "sasl-server.h"
#include "sasl-server-gssapi.h"
#include "sasl-server-oauth2.h"
#include "dsasl-client.h"
#include "dsasl-client-mech-ntlm-dummy.h"
#include "fuzzer.h"

#include <unistd.h>
#include <fcntl.h>

enum fuzz_sasl_modification {
	FUZZ_SASL_MOD_DELETE = 0,
	FUZZ_SASL_MOD_REPLACE,
	FUZZ_SASL_MOD_INSERT,
	FUZZ_SASL_MOD_APPEND,
	FUZZ_SASL_MOD_XOR,
};

struct fuzz_sasl_parameters {
	const char *mech;
	enum sasl_server_authid_type authid_type;
	const char *authid;
	const char *authzid;
	const char *server_password;
	const char *client_password;
	const char *server_cbind_data;
	const char *client_cbind_data;
};

struct fuzz_sasl_context {
	pool_t pool;

	struct sasl_server_req_ctx ssrctx;
	const struct fuzz_sasl_parameters *params;

	struct dsasl_client *client;

	const char *server_cbind_type;
	const char *authid;
	const char *authzid;

	struct istream *fuzz_input;

	bool auth_initial:1;
	bool out_of_band_cycle:1;
	bool finished:1;
	bool auth_success:1;
};

static struct event *fuzz_event;

static buffer_t *
fuzz_create_channel_binding_data(struct fuzz_sasl_context *fctx,
				 const char *type, const char *data)
{
	buffer_t *cbind_data;
	string_t *str = t_str_new(256);

	str_append(str, type);
	str_append_c(str, ':');
	str_append(str, data);

	cbind_data = buffer_create_dynamic(fctx->pool,
		MAX_BASE64_ENCODED_SIZE(strlen(type) + 1 + strlen(data)));
	base64_encode(str_data(str), str_len(str), cbind_data);

	return cbind_data;
}

static bool
fuzz_server_request_set_authid(struct sasl_server_req_ctx *rctx,
			       enum sasl_server_authid_type authid_type,
			       const char *authid)
{
	struct fuzz_sasl_context *fctx =
		container_of(rctx, struct fuzz_sasl_context, ssrctx);

	if (fctx->params->authid_type != authid_type)
		return FALSE;

	fctx->authid = p_strdup(fctx->pool, authid);
	return TRUE;
}

static bool
fuzz_server_request_set_authzid(struct sasl_server_req_ctx *rctx,
				const char *authzid)
{
	struct fuzz_sasl_context *fctx =
		container_of(rctx, struct fuzz_sasl_context, ssrctx);

	if (fctx->params->authzid == NULL)
		return FALSE;

	fctx->authzid = p_strdup(fctx->pool, authzid);
	return TRUE;
}

static void
fuzz_server_request_set_realm(struct sasl_server_req_ctx *rctx ATTR_UNUSED,
			      const char *realm ATTR_UNUSED)
{
	/* Realm not part of fuzz yet */
}

static bool
fuzz_server_request_get_extra_field(struct sasl_server_req_ctx *rctx ATTR_UNUSED,
				    const char *name ATTR_UNUSED,
				    const char **field_r ATTR_UNUSED)
{
	return FALSE;
}

static void
fuzz_server_request_start_channel_binding(struct sasl_server_req_ctx *rctx,
					  const char *type)
{
	struct fuzz_sasl_context *fctx =
		container_of(rctx, struct fuzz_sasl_context, ssrctx);

	i_assert(fctx->server_cbind_type == NULL);
	fctx->server_cbind_type = p_strdup(fctx->pool, type);
}

static int
fuzz_server_request_accept_channel_binding(struct sasl_server_req_ctx *rctx,
					   buffer_t **data_r)
{
	struct fuzz_sasl_context *fctx =
		container_of(rctx, struct fuzz_sasl_context, ssrctx);

	if (fctx->server_cbind_type == NULL)
		return -1;

	*data_r = fuzz_create_channel_binding_data(
		fctx, fctx->server_cbind_type,
		fctx->params->server_cbind_data);
	return 0;
}

static void
fuzz_server_request_verify_plain(struct sasl_server_req_ctx *rctx,
				 const char *password,
				 sasl_server_passdb_callback_t *callback)
{
	struct fuzz_sasl_context *fctx =
		container_of(rctx, struct fuzz_sasl_context, ssrctx);
	struct sasl_passdb_result result;

	i_zero(&result);
	if (null_strcmp(fctx->authid, fctx->params->authid) != 0 ||
	    null_strcmp(fctx->authzid, fctx->params->authzid) != 0) {
		result.status = SASL_PASSDB_RESULT_USER_UNKNOWN;
		callback(&fctx->ssrctx, &result);
		return;
	}
	if (strcmp(fctx->params->server_password, password) != 0) {
		result.status = SASL_PASSDB_RESULT_PASSWORD_MISMATCH;
		callback(&fctx->ssrctx, &result);
		return;
	}

	result.status = SASL_PASSDB_RESULT_OK;
	callback(&fctx->ssrctx, &result);
}

static void
fuzz_server_request_lookup_credentials(
	struct sasl_server_req_ctx *rctx, const char *scheme,
	sasl_server_passdb_callback_t *callback)
{
	struct fuzz_sasl_context *fctx =
		container_of(rctx, struct fuzz_sasl_context, ssrctx);
	struct sasl_passdb_result result;

	i_zero(&result);

#ifdef HAVE_GSSAPI
	if (strcmp(fctx->params->mech, SASL_MECH_NAME_GSSAPI) == 0) {
		i_assert(*scheme == '\0');
		result.status = SASL_PASSDB_RESULT_OK;
		callback(&fctx->ssrctx, &result);
		return;
	}
#endif

	if (null_strcmp(fctx->authid, fctx->params->authid) != 0 ||
	    null_strcmp(fctx->authzid, fctx->params->authzid) != 0) {
		result.status = SASL_PASSDB_RESULT_USER_UNKNOWN;
		callback(&fctx->ssrctx, &result);
		return;
	}

	const struct password_generate_params params = {
		.user = fctx->params->authid,
	};

	if (!password_generate(fctx->params->server_password, &params, scheme,
			       &result.credentials.data,
			       &result.credentials.size)) {
		i_zero(&result);
		result.status = SASL_PASSDB_RESULT_INTERNAL_FAILURE;
		callback(&fctx->ssrctx, &result);
		return;
	}

	result.status = SASL_PASSDB_RESULT_OK;
	callback(&fctx->ssrctx, &result);
}

static void
fuzz_server_request_set_credentials(
	struct sasl_server_req_ctx *rctx,
	const char *scheme ATTR_UNUSED, const char *data ATTR_UNUSED,
	sasl_server_passdb_callback_t *callback)
{
	struct fuzz_sasl_context *fctx =
		container_of(rctx, struct fuzz_sasl_context, ssrctx);
	struct sasl_passdb_result result;

	/* Credentials are currently not actually stored */

	i_zero(&result);
	result.status = SASL_PASSDB_RESULT_OK;
	callback(&fctx->ssrctx, &result);
}

static void
fuzz_sasl_amend_data(struct fuzz_sasl_context *fctx,
		     const unsigned char **_data, size_t *_size)
{
	struct istream *input = fctx->fuzz_input;
	const unsigned char *mod_data;
	size_t mod_size;
	int ret;

	/* read block size */
	ret = i_stream_read_bytes(input, &mod_data, &mod_size, 2);
	i_assert(ret != 0 && ret != -2);
	if (ret < 0) {
		i_assert(input->eof);
		e_debug(fuzz_event, "data not modified (no more fuzz input)");
		return;
	}

	size_t block_size = (size_t)mod_data[0] << 8 | (size_t)mod_data[1];
	i_stream_skip(input, 2);

	if (block_size == 0)
		return;

	/* read block data */
	ret = i_stream_read_bytes(input, &mod_data, &mod_size, block_size);
	i_assert(ret != 0 && ret != -2);
	if (ret < 0) {
		e_debug(fuzz_event, "data not modified (no more fuzz input)");
		i_assert(input->eof);
		return;
	}

	const unsigned char *mp = mod_data, *mpend = mod_data + block_size;
	const unsigned char *data = *_data;
	size_t size = *_size;
	buffer_t *buf1, *buf2, *buft;
	bool modified = FALSE;

	buf1 = buffer_create_dynamic(default_pool, size * 2);
	buf2 = buffer_create_dynamic(default_pool, size * 2);
	while (mp + 5 < mpend) {
		/* parse operation */
		uint8_t op = *mp & 0x07;
		mp++;
		size_t op_offset = (size_t)mp[0] << 8 | (size_t)mp[1];
		mp += 2;
		size_t op_size = (size_t)mp[0] << 8 | (size_t)mp[1];
		mp += 2;

		if (mp >= mpend)
			break;
		if (op_size == 0)
			continue;
		if (op != FUZZ_SASL_MOD_DELETE &&
		    op_size > (size_t)(mpend - mp))
			op_size = (mpend - mp);
		if (op != FUZZ_SASL_MOD_APPEND && op_offset >= size) {
			if (op != FUZZ_SASL_MOD_DELETE)
				mp += op_size;
			continue;
		}

		unsigned char *mdata;
		size_t msize, di;
		switch (op) {
		case FUZZ_SASL_MOD_DELETE:
			msize = I_MIN(size - op_offset, op_size);
			e_debug(fuzz_event, "data modified: delete %zu:%zu",
				op_offset, op_offset + msize);
			buffer_append(buf1, data, op_offset);
			if (op_offset + msize < size) {
				buffer_append(
					buf1, &data[op_offset + msize],
					size - (op_offset + msize));
			}
			modified = TRUE;
			break;
		case FUZZ_SASL_MOD_REPLACE:
			e_debug(fuzz_event, "data modified: replace %zu:%zu",
				op_offset, op_offset + op_size);
			buffer_append(buf1, data, op_offset);
			msize = I_MIN(size - op_offset, op_size);
			buffer_append(buf1, mp, msize);
			if (op_offset + op_size < size) {
				buffer_append(
					buf1, &data[op_offset + op_size],
					size - (op_offset + op_size));
			}
			mp += op_size;
			modified = TRUE;
			break;
		case FUZZ_SASL_MOD_INSERT:
			e_debug(fuzz_event, "data modified: insert %zu size=%zu",
				op_offset, op_size);
			buffer_append(buf1, data, op_offset);
			buffer_append(buf1, mp, op_size);
			buffer_append(buf1, &data[op_offset],
				      size - op_offset);
			mp += op_size;
			modified = TRUE;
			break;
		case FUZZ_SASL_MOD_APPEND:
			e_debug(fuzz_event, "data modified: append size=%zu",
				op_size);
			buffer_append(buf1, data, size);
			buffer_append(buf1, mp, op_size);
			mp += op_size;
			modified = TRUE;
			break;
		case FUZZ_SASL_MOD_XOR:
			e_debug(fuzz_event, "data modified: xor %zu:%zu",
				op_offset, op_offset + op_size);
			mdata = buffer_append_space_unsafe(buf1, size);
			memcpy(mdata, data, size);
			msize = I_MIN(size - op_offset, op_size);
			for (di = op_offset; di < op_offset + msize; di++, mp++)
				mdata[di] = mdata[di] ^ *mp;
			modified = TRUE;
			break;
		default:
			mp += op_size;
			break;
		}

		buft = buf1; buf1 = buf2; buf2 = buft;
		data = buf2->data;
		size = buf2->used;
		buffer_clear(buf1);
	}
	i_stream_skip(input, block_size);

	if (!modified) {
		e_debug(fuzz_event, "data not modified "
			"(no suitable instructions)");
	} else {
		if (buf2->used > 0)
			*_data = t_memdup(buf2->data, buf2->used);
		else
			*_data = uchar_empty_ptr;
		*_size = buf2->used;
	}
	buffer_free(&buf1);
	buffer_free(&buf2);
}

static void
fuzz_server_request_output(struct sasl_server_req_ctx *rctx,
			   const struct sasl_server_output *output)
{
	struct fuzz_sasl_context *fctx =
		container_of(rctx, struct fuzz_sasl_context, ssrctx);
	bool failed = FALSE;
	enum dsasl_client_result result;

	switch (output->status) {
	case SASL_SERVER_OUTPUT_INTERNAL_FAILURE:
	case SASL_SERVER_OUTPUT_PASSWORD_MISMATCH:
	case SASL_SERVER_OUTPUT_FAILURE:
		e_debug(fuzz_event, "server input/output failure");
		fctx->finished = TRUE;
		failed = TRUE;
		break;
	case SASL_SERVER_OUTPUT_SUCCESS:
		if (strcasecmp(fctx->params->mech, SASL_MECH_NAME_ANONYMOUS) != 0 &&
		    strcasecmp(fctx->params->mech, SASL_MECH_NAME_PLAIN) != 0 &&
		    strcasecmp(fctx->params->mech, SASL_MECH_NAME_LOGIN) != 0 &&
		    strcasecmp(fctx->params->mech, SASL_MECH_NAME_NTLM) != 0) {
			/* hash-based mechanisms should never be able to get
			   here when password is wrong */
			i_assert(strcmp(fctx->params->client_password,
					fctx->params->server_password) == 0);
		}
		fctx->auth_success = TRUE;
		fctx->finished = TRUE;
		/* fall through */
	case SASL_SERVER_OUTPUT_CONTINUE:
		e_debug(fuzz_event, "server input/output success");
		break;
	}

	if (failed)
		;
	else if (output->data_size == 0 && output->data == NULL)
		fctx->out_of_band_cycle = TRUE;
	else if (output->data_size > 0) {
		const unsigned char *data = output->data;
		size_t size = output->data_size;
		const char *error = NULL;

		fuzz_sasl_amend_data(fctx, &data, &size);
		result = dsasl_client_input(fctx->client, data, size, &error);
		if (result != DSASL_CLIENT_RESULT_OK) {
			e_debug(fuzz_event, "client input error: %s", error);
			fctx->finished = TRUE;
		} else {
			e_debug(fuzz_event, "client input success");
		}
	}
}

static int
fuzz_server_oauth2_auth_new(struct sasl_server_req_ctx *rctx,
			    pool_t pool ATTR_UNUSED, const char *token,
			    struct sasl_server_oauth2_request **req_r)
{
	struct fuzz_sasl_context *fctx =
		container_of(rctx, struct fuzz_sasl_context, ssrctx);

	*req_r = NULL;

	if (null_strcmp(fctx->authid, fctx->params->authid) != 0 ||
	    null_strcmp(fctx->authzid, fctx->params->authzid) != 0 ||
	    strcmp(fctx->params->server_password, token) != 0) {
		const struct sasl_server_oauth2_failure failure = {
			.status = "invalid_token",
		};
		sasl_server_oauth2_request_fail(rctx, &failure);
		return -1;
	}
	sasl_server_oauth2_request_succeed(rctx);
	return 0;
}

struct sasl_server_oauth2_funcs server_oauth2_funcs = {
	.auth_new = fuzz_server_oauth2_auth_new,
};

struct sasl_server_request_funcs server_funcs = {
	.request_set_authid = fuzz_server_request_set_authid,
	.request_set_authzid = fuzz_server_request_set_authzid,
	.request_set_realm = fuzz_server_request_set_realm,

	.request_get_extra_field = fuzz_server_request_get_extra_field,

	.request_start_channel_binding =
		fuzz_server_request_start_channel_binding,
	.request_accept_channel_binding =
		fuzz_server_request_accept_channel_binding,

	.request_verify_plain = fuzz_server_request_verify_plain,
	.request_lookup_credentials = fuzz_server_request_lookup_credentials,
	.request_set_credentials = fuzz_server_request_set_credentials,

	.request_output = fuzz_server_request_output,
};

static int
fuzz_client_channel_binding_callback(const char *type, void *context,
				     const buffer_t **data_r,
				     const char **error_r)
{
	struct fuzz_sasl_context *fctx = context;

	*data_r = fuzz_create_channel_binding_data(
		fctx, type, fctx->params->client_cbind_data);
	*error_r = NULL;
	return 0;
}

static void fuzz_sasl_interact(struct fuzz_sasl_context *fctx)
{
	const unsigned char *sasl_data = NULL;
	size_t sasl_data_size = 0;
	const char *error = NULL;
	bool failed = FALSE;
	enum dsasl_client_result result;

	if (fctx->auth_initial) {
		result = dsasl_client_output(fctx->client,
					  &sasl_data, &sasl_data_size,
					  &error);
		if (result != DSASL_CLIENT_RESULT_OK) {
			e_debug(fuzz_event, "client initial error: %s", error);
			fctx->finished = TRUE;
			failed = TRUE;
		} else {
			e_debug(fuzz_event, "client initial success");
		}

		if (!failed)
			fuzz_sasl_amend_data(fctx, &sasl_data, &sasl_data_size);
	}
	sasl_server_request_initial(&fctx->ssrctx,
				    sasl_data, sasl_data_size);

	while (!fctx->finished) {
		sasl_data = NULL;
		sasl_data_size = 0;

		if (!fctx->out_of_band_cycle) {
			result = dsasl_client_output(
				fctx->client, &sasl_data, &sasl_data_size,
				&error);
			if (result != DSASL_CLIENT_RESULT_OK) {
				e_debug(fuzz_event, "client output error: %s",
					error);
				fctx->finished = TRUE;
				return;
			} else {
				e_debug(fuzz_event, "client output success");
			}
			fuzz_sasl_amend_data(fctx, &sasl_data, &sasl_data_size);
		}

		sasl_server_request_input(&fctx->ssrctx,
					  sasl_data, sasl_data_size);
	}
}

static void fuzz_sasl_run(struct istream *input)
{
	struct fuzz_sasl_parameters params;
	bool auth_initial = FALSE;
	const char *line;

	i_zero(&params);
	params.authid_type = SASL_SERVER_AUTHID_TYPE_USERNAME;

	line = i_stream_read_next_line(input);
	if (line == NULL || *line == '\0')
		return;
	params.mech = t_strdup(line);

	line = i_stream_read_next_line(input);
	if (line == NULL || *line == '\0')
		return;
	params.authid = t_strdup(line);

	line = i_stream_read_next_line(input);
	if (line == NULL)
		return;
	params.authzid = t_strdup_empty(line);

	line = i_stream_read_next_line(input);
	if (line == NULL)
		return;
	params.server_password = t_strdup(line);

	line = i_stream_read_next_line(input);
	if (line == NULL)
		return;
	if (*line == '\0')
		params.client_password = params.server_password;
	else
		params.client_password = t_strdup(line);

	line = i_stream_read_next_line(input);
	if (line == NULL)
		return;
	params.server_cbind_data = t_strdup(line);

	line = i_stream_read_next_line(input);
	if (line == NULL)
		return;
	if (*line == '\0')
		params.client_cbind_data = params.server_cbind_data;
	else
		params.client_cbind_data = t_strdup(line);

	line = i_stream_read_next_line(input);
	if (line == NULL)
		return;
	auth_initial = (strlen(line) > 0);

	struct sasl_server_settings server_set;
	struct sasl_server *server;
	struct sasl_server_instance *server_inst;

	i_zero(&server_set);
	server = sasl_server_init(fuzz_event, &server_funcs);
	server_inst = sasl_server_instance_create(server, &server_set);

	sasl_server_mech_register_anonymous(server_inst);
	sasl_server_mech_register_cram_md5(server_inst);
	sasl_server_mech_register_digest_md5(server_inst);
	sasl_server_mech_register_login(server_inst);
	sasl_server_mech_register_otp(server_inst);
	sasl_server_mech_register_plain(server_inst);
	sasl_server_mech_register_scram_sha1(server_inst);
	sasl_server_mech_register_scram_sha1_plus(server_inst);
	sasl_server_mech_register_scram_sha256(server_inst);
	sasl_server_mech_register_scram_sha256_plus(server_inst);

	const struct sasl_server_oauth2_settings oauth2_set = {
		.openid_configuration_url = "http://example.org/openid",
	};
	sasl_server_mech_register_oauthbearer(server_inst,
					      &server_oauth2_funcs,
					      &oauth2_set);
	sasl_server_mech_register_xoauth2(server_inst,
					  &server_oauth2_funcs, &oauth2_set);

	struct sasl_server_winbind_settings winbind_set;

	i_zero(&winbind_set);
	winbind_set.helper_path = TEST_WINBIND_HELPER_PATH;
	sasl_server_mech_register_winbind_ntlm(server_inst, &winbind_set);

#ifdef HAVE_GSSAPI
	struct sasl_server_gssapi_settings gssapi_set;

	i_zero(&gssapi_set);
	gssapi_set.hostname = "localhost";
	sasl_server_mech_register_gssapi(server_inst, &gssapi_set);
#endif

	const struct sasl_server_mech *server_mech;

	server_mech = sasl_server_mech_find(server_inst, params.mech);
	if (server_mech == NULL) {
		sasl_server_instance_unref(&server_inst);
		sasl_server_deinit(&server);
		return;
	}

	e_debug(fuzz_event, "run: %s", str_sanitize(params.mech, 1024));

#ifdef HAVE_GSSAPI
	if (strcmp(params.mech, SASL_MECH_NAME_GSSAPI) == 0) {
		gss_dummy_add_principal(params.authid);
		gss_dummy_kinit(params.authid);
	}
#endif

	const struct dsasl_client_mech *client_mech;
	struct fuzz_sasl_context fctx;

	i_zero(&fctx);
	fctx.pool = pool_alloconly_create(MEMPOOL_GROWING"fuzz_sasl", 2048);
	fctx.params = &params;
	fctx.fuzz_input = input;
	fctx.auth_initial = auth_initial;

	sasl_server_request_create(&fctx.ssrctx, server_mech, "imap", NULL);

	struct dsasl_client_settings client_set = {
		.event_parent = fuzz_event,
		.authid = params.authid,
		.authzid = params.authzid,
		.password = params.client_password,
		.protocol = "imap",
		.host = "example.com",
	};
	client_mech = dsasl_client_mech_find(params.mech);
	if (client_mech != NULL) {
		fctx.client = dsasl_client_new(client_mech, &client_set);
		i_assert(fctx.client != NULL);

		dsasl_client_enable_channel_binding(
			fctx.client, SSL_IOSTREAM_PROTOCOL_VERSION_TLS1_3,
			fuzz_client_channel_binding_callback, &fctx);

		fuzz_sasl_interact(&fctx);
	}

	dsasl_client_free(&fctx.client);
	sasl_server_request_destroy(&fctx.ssrctx);

	sasl_server_instance_unref(&server_inst);
	sasl_server_deinit(&server);

	if (fctx.auth_success) {
		e_debug(fuzz_event, "run: %s autentication successful",
			str_sanitize(params.mech, 1024));
	} else {
		e_debug(fuzz_event, "run: %s autentication failed",
			str_sanitize(params.mech, 1024));
	}

	pool_unref(&fctx.pool);
#ifdef HAVE_GSSAPI
	gss_dummy_deinit();
#endif
}

FUZZ_BEGIN_DATA(const unsigned char *data, size_t size)
{
	fuzz_event = event_create(NULL);
	event_set_forced_debug(fuzz_event, TRUE);

	password_schemes_init();
	dsasl_clients_init();
	dsasl_client_mech_ntlm_init_dummy();
#ifdef HAVE_GSSAPI
	dsasl_clients_init_gssapi();
#endif

	struct istream *input = i_stream_create_from_data(data, size);
	struct ioloop *ioloop = io_loop_create();

	T_BEGIN {
		fuzz_sasl_run(input);
	} T_END;

	io_loop_destroy(&ioloop);
	i_stream_unref(&input);

	dsasl_clients_deinit();
	password_schemes_deinit();

	event_unref(&fuzz_event);
}
FUZZ_END
