/* Copyright (c) 2025 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "str-sanitize.h"
#include "buffer.h"
#include "auth-gssapi.h"

#include "dsasl-client-private.h"

/* Non-zero flags defined in RFC 2222 */
enum sasl_gssapi_qop {
	SASL_GSSAPI_QOP_UNSPECIFIED = 0x00,
	SASL_GSSAPI_QOP_AUTH_ONLY   = 0x01,
	SASL_GSSAPI_QOP_AUTH_INT    = 0x02,
	SASL_GSSAPI_QOP_AUTH_CONF   = 0x04
};

enum gssapi_gs1_client_state {
	GSSAPI_GS1_CLIENT_STATE_INIT = 0,
	GSSAPI_GS1_CLIENT_STATE_SEC_CONTEXT,
	GSSAPI_GS1_CLIENT_STATE_UNWRAP,
	GSSAPI_GS1_CLIENT_STATE_WRAP,
	GSSAPI_GS1_CLIENT_STATE_END,
};

struct gssapi_sasl_client {
	struct dsasl_client client;

	union {
		enum gssapi_gs1_client_state gs1;
	} state;

	gss_name_t gss_principal;
	gss_ctx_id_t gss_ctx;

	buffer_t *out_buf;
};

static void
mech_gssapi_error_append(string_t *msg, unsigned int *entries,
			 OM_uint32 status_value, int status_type)
{
	OM_uint32 major_status, minor_status;
	OM_uint32 message_context = 0;
	gss_buffer_desc status_string;

	do {
		major_status = gss_display_status(&minor_status, status_value,
						  status_type, GSS_C_NO_OID,
						  &message_context,
						  &status_string);
		if (major_status == GSS_S_COMPLETE &&
		    status_string.length > 0) {
			if ((*entries)++ > 0)
				str_append(msg, "; ");
			str_append(msg, str_sanitize(status_string.value,
						     status_string.length));
		}
		(void)gss_release_buffer(&minor_status, &status_string);
	} while (GSS_ERROR(major_status) == 0 && message_context != 0);
}

static const char *
mech_gssapi_error(const char *description, OM_uint32 major_status,
		  OM_uint32 minor_status)
{
	string_t *msg = t_str_new(128);
	unsigned int entries = 0;

	str_append(msg, "While ");
	str_append(msg, description);
	str_append(msg, ": ");

	if (major_status != GSS_S_FAILURE) {
		mech_gssapi_error_append(msg, &entries, major_status,
					 GSS_C_GSS_CODE);
	}
	mech_gssapi_error_append(msg, &entries, minor_status, GSS_C_MECH_CODE);

	return str_c(msg);
}

static enum dsasl_client_result
mech_gssapi_gs1_init(struct gssapi_sasl_client *gclient, gss_buffer_t in_buf,
		     const char **error_r)
{
	struct dsasl_client *client = &gclient->client;
	OM_uint32 major_status, minor_status;
	string_t *principal_name;
	gss_buffer_desc namebuf;

	gclient->gss_ctx = GSS_C_NO_CONTEXT;
	gclient->gss_principal = GSS_C_NO_NAME;

	if (in_buf->length > 0) {
		*error_r = "Unexpected initial server challenge";
		return DSASL_CLIENT_RESULT_ERR_PROTOCOL;
	}

	principal_name = t_str_new(128);
	str_append(principal_name, client->set.protocol);
	str_append_c(principal_name, '@');
	str_append(principal_name, client->set.host);

	namebuf.length = str_len(principal_name);
	namebuf.value = str_c_modifiable(principal_name);

	major_status = gss_import_name(&minor_status, &namebuf,
				       GSS_C_NT_HOSTBASED_SERVICE,
				       &gclient->gss_principal);
	if (GSS_ERROR(major_status) != 0) {
		*error_r = mech_gssapi_error("importing principal name",
					     major_status, minor_status);
		return DSASL_CLIENT_RESULT_ERR_PROTOCOL;
	}

	e_debug(client->event, "Successfully imported principal name");

	gclient->out_buf = buffer_create_dynamic(default_pool, 1024);
	gclient->state.gs1 = GSSAPI_GS1_CLIENT_STATE_SEC_CONTEXT;
	return DSASL_CLIENT_RESULT_OK;
}

static int
mech_gssapi_sec_context(struct gssapi_sasl_client *gclient,
			gss_buffer_t in_buf, gss_buffer_t out_buf,
			const char **error_r)
{
	struct dsasl_client *client = &gclient->client;
	OM_uint32 major_status, minor_status;
	OM_uint32 req_flags = GSS_C_REPLAY_FLAG | GSS_C_MUTUAL_FLAG |
			      GSS_C_SEQUENCE_FLAG | GSS_C_INTEG_FLAG;
	gss_OID_desc mech_oid = *auth_gssapi_mech_krb5_oid;
	gss_OID ret_mech_oid;

	major_status = gss_init_sec_context(&minor_status, GSS_C_NO_CREDENTIAL,
					    &gclient->gss_ctx,
					    gclient->gss_principal,
					    &mech_oid, req_flags,
					    0, GSS_C_NO_CHANNEL_BINDINGS,
					    in_buf, &ret_mech_oid, out_buf,
					    NULL, NULL);
	if(GSS_ERROR(major_status) != 0) {
		(void)gss_release_buffer(&minor_status, out_buf);
		*error_r = mech_gssapi_error((in_buf->length == 0 ?
					      "initializing security context" :
					      "processing incoming data"),
					     major_status, minor_status);
		return -1;
	}

	switch (major_status) {
	case GSS_S_COMPLETE:
		i_assert(ret_mech_oid != NULL);
		if (!auth_gssapi_oid_equal(ret_mech_oid,
					   auth_gssapi_mech_krb5_oid)) {
			*error_r = "GSSAPI mechanism not Kerberos5";
			return -1;
		}
		e_debug(client->event,
			"Security context state completed");
		break;
	case GSS_S_CONTINUE_NEEDED:
		e_debug(client->event,
			"Processed incoming packet correctly, "
			"waiting for another");
		return 0;
	default:
		i_unreached();
	}

	return 1;
}

static enum dsasl_client_result
mech_gssapi_gs1_sec_context(struct gssapi_sasl_client *gclient,
			    gss_buffer_t in_buf, const char **error_r)
{
	OM_uint32 minor_status;
	gss_buffer_desc out_buf;
	int ret;

	ret = mech_gssapi_sec_context(gclient, in_buf, &out_buf, error_r);
	if (ret < 0)
		return DSASL_CLIENT_RESULT_ERR_PROTOCOL;

	buffer_append(gclient->out_buf, out_buf.value, out_buf.length);
	(void)gss_release_buffer(&minor_status, &out_buf);

	if (ret > 0)
		gclient->state.gs1 = GSSAPI_GS1_CLIENT_STATE_UNWRAP;

	return DSASL_CLIENT_RESULT_OK;
}

static enum dsasl_client_result
mech_gssapi_gs1_unwrap(struct gssapi_sasl_client *gclient,
		       gss_buffer_t in_buf, const char **error_r)
{
	struct dsasl_client *client = &gclient->client;
	OM_uint32 major_status, minor_status;
	gss_buffer_desc in_buf_wrap = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc out_buf = GSS_C_EMPTY_BUFFER;
	gss_qop_t qop = GSS_C_QOP_DEFAULT;
	unsigned char *data;
	unsigned int sec_layer = 0;
	unsigned int max_size = 0;
	buffer_t *buf;
	size_t authzid_size = (client->set.authzid == NULL ?
			       0 : strlen(client->set.authzid));

	/* Decrypt the inbound challenge and obtain the qop */
	major_status = gss_unwrap(&minor_status, gclient->gss_ctx, in_buf,
				  &out_buf, NULL, &qop);
	if(GSS_ERROR(major_status) != 0) {
		*error_r = mech_gssapi_error(
			"receiving security layer negotiation",
			major_status, minor_status);
		return DSASL_CLIENT_RESULT_ERR_PROTOCOL;
	}

	if (out_buf.length != 4) {
		*error_r = "Bad server message: Invalid security data";
		return DSASL_CLIENT_RESULT_ERR_PROTOCOL;
	}

	data = out_buf.value;
	sec_layer = data[0];
	max_size = (data[1] << 16) | (data[2] << 8) | data[3];
	(void)gss_release_buffer(&minor_status, &out_buf);

	/* Check server parameters */
	if((sec_layer & SASL_GSSAPI_QOP_AUTH_ONLY) == 0) {
		*error_r = "Server demands unsupported security parameters";
		return DSASL_CLIENT_RESULT_ERR_PROTOCOL;
	}
	sec_layer = SASL_GSSAPI_QOP_AUTH_ONLY;
	max_size = 0;

	buf = t_buffer_create(4 + authzid_size);
	buffer_append_c(buf, sec_layer);
	buffer_append_c(buf, max_size >> 16);
	buffer_append_c(buf, max_size >> 8);
	buffer_append_c(buf, max_size >> 0);
	if (client->set.authzid != NULL)
		buffer_append(buf, client->set.authzid, authzid_size);

	/* Setup the "authentication data" security buffer */
	in_buf_wrap.value =
		buffer_get_modifiable_data(buf, &in_buf_wrap.length);

	/* Encrypt the data */
	major_status = gss_wrap(&minor_status, gclient->gss_ctx, 0,
				GSS_C_QOP_DEFAULT, &in_buf_wrap, NULL,
				&out_buf);
	if (GSS_ERROR(major_status) != 0) {
		*error_r = mech_gssapi_error(
			"sending security layer negotiation",
			major_status, minor_status);
		return DSASL_CLIENT_RESULT_ERR_INTERNAL;
	}

	e_debug(client->event, "Negotiated security layer");

	buffer_clear(gclient->out_buf);
	buffer_append(gclient->out_buf, out_buf.value, out_buf.length);
	(void)gss_release_buffer(&minor_status, &out_buf);

	gclient->state.gs1 = GSSAPI_GS1_CLIENT_STATE_WRAP;
	return DSASL_CLIENT_RESULT_OK;
}

static enum dsasl_client_result
mech_gssapi_gs1_input(struct dsasl_client *client,
		      const unsigned char *input, size_t input_len,
		      const char **error_r)
{
	struct gssapi_sasl_client *gclient =
		container_of(client, struct gssapi_sasl_client, client);
	gss_buffer_desc in_buf;
	enum dsasl_client_result result = DSASL_CLIENT_RESULT_ERR_INTERNAL;

	in_buf.value = (void *)input;
	in_buf.length = input_len;

	switch (gclient->state.gs1) {
	case GSSAPI_GS1_CLIENT_STATE_INIT:
		result = mech_gssapi_gs1_init(gclient, &in_buf, error_r);
		break;
	case GSSAPI_GS1_CLIENT_STATE_SEC_CONTEXT:
		result = mech_gssapi_gs1_sec_context(gclient, &in_buf, error_r);
		break;
	case GSSAPI_GS1_CLIENT_STATE_UNWRAP:
		result = mech_gssapi_gs1_unwrap(gclient, &in_buf, error_r);
		break;
	case GSSAPI_GS1_CLIENT_STATE_WRAP:
	case GSSAPI_GS1_CLIENT_STATE_END:
	default:
		i_unreached();
	}
	return result;
}

static enum dsasl_client_result
mech_gssapi_gs1_output(struct dsasl_client *client,
		       const unsigned char **output_r, size_t *output_len_r,
		       const char **error_r)
{
	struct gssapi_sasl_client *gclient =
		container_of(client, struct gssapi_sasl_client, client);
	gss_buffer_desc in_buf = GSS_C_EMPTY_BUFFER;
	enum dsasl_client_result result = DSASL_CLIENT_RESULT_ERR_INTERNAL;

	switch (gclient->state.gs1) {
	case GSSAPI_GS1_CLIENT_STATE_INIT:
		result = mech_gssapi_gs1_init(gclient, &in_buf, error_r);
		if (result != DSASL_CLIENT_RESULT_OK)
			return result;
		i_assert(gclient->state.gs1 ==
			 GSSAPI_GS1_CLIENT_STATE_SEC_CONTEXT);
		result = mech_gssapi_gs1_sec_context(gclient, &in_buf, error_r);
		if (result != DSASL_CLIENT_RESULT_OK)
			return result;
		break;
	case GSSAPI_GS1_CLIENT_STATE_SEC_CONTEXT:
	case GSSAPI_GS1_CLIENT_STATE_UNWRAP:
	case GSSAPI_GS1_CLIENT_STATE_WRAP:
		break;
	case GSSAPI_GS1_CLIENT_STATE_END:
	default:
		i_unreached();
	}

	*output_r = gclient->out_buf->data;
	*output_len_r = gclient->out_buf->used;
	return DSASL_CLIENT_RESULT_OK;
}

static void mech_gssapi_free(struct dsasl_client *client)
{
	struct gssapi_sasl_client *gclient =
		container_of(client, struct gssapi_sasl_client, client);
	OM_uint32 minor_status;

	if (gclient->gss_ctx != GSS_C_NO_CONTEXT) {
		(void)gss_delete_sec_context(&minor_status, &gclient->gss_ctx,
					     GSS_C_NO_BUFFER);
	}
	if (gclient->gss_principal != GSS_C_NO_NAME)
		(void)gss_release_name(&minor_status, &gclient->gss_principal);
	buffer_free(&gclient->out_buf);
}

static const struct dsasl_client_mech dsasl_client_mech_gssapi = {
	.name = "GSSAPI",
	.flags = DSASL_MECH_SEC_ALLOW_NULS,
	.struct_size = sizeof(struct gssapi_sasl_client),

	.input = mech_gssapi_gs1_input,
	.output = mech_gssapi_gs1_output,
	.free = mech_gssapi_free,
};

static bool initialized = FALSE;

void dsasl_clients_init_gssapi(void)
{
	if (initialized)
		return;

	initialized = TRUE;
	dsasl_client_mech_register(&dsasl_client_mech_gssapi);
}
