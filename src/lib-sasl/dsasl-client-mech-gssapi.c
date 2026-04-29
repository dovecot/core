/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "str.h"
#include "str-sanitize.h"
#include "buffer.h"
#include "auth-gssapi.h"

#include "dsasl-client-protected.h"

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

struct gssapi_sasl_session {
	struct dsasl_client_mech_session session;

	union {
		enum gssapi_gs1_client_state gs1;
	} state;

	gss_name_t gss_principal;
	gss_ctx_id_t gss_ctx;

	buffer_t *out_buf;
};

static const struct dsasl_client_mech dsasl_client_mech_gssapi;
static const struct dsasl_client_mech dsasl_client_mech_gss_spnego;

static struct dsasl_client_mech_session *mech_gssapi_auth_new(pool_t pool)
{
	struct gssapi_sasl_session *gsession =
		p_new(pool, struct gssapi_sasl_session, 1);
	return &gsession->session;
}

static void mech_gssapi_auth_free(struct dsasl_client_mech_session *msession)
{
	struct gssapi_sasl_session *gsession =
		container_of(msession, struct gssapi_sasl_session, session);
	OM_uint32 minor_status;

	if (gsession->gss_ctx != GSS_C_NO_CONTEXT) {
		(void)gss_delete_sec_context(&minor_status, &gsession->gss_ctx,
					     GSS_C_NO_BUFFER);
	}
	if (gsession->gss_principal != GSS_C_NO_NAME)
		(void)gss_release_name(&minor_status, &gsession->gss_principal);
	buffer_free(&gsession->out_buf);
}

static int
mech_gssapi_auth_check(struct dsasl_client_mech_session *msession,
		       const char **error_r)
{
	if (msession->params.protocol == NULL) {
		*error_r = "protocol not set";
		return -1;
	}
	if (msession->params.host == NULL) {
		*error_r = "host not set";
		return -1;
	}
	return 0;
}

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
mech_gssapi_gs1_init(struct gssapi_sasl_session *gsession, gss_buffer_t in_buf,
		     const char **error_r)
{
	struct dsasl_client_mech_session *msession = &gsession->session;
	OM_uint32 major_status, minor_status;
	string_t *principal_name;
	gss_buffer_desc namebuf;

	gsession->gss_ctx = GSS_C_NO_CONTEXT;
	gsession->gss_principal = GSS_C_NO_NAME;

	if (in_buf->length > 0) {
		*error_r = "Unexpected initial server challenge";
		return DSASL_CLIENT_RESULT_ERR_PROTOCOL;
	}

	principal_name = t_str_new(128);
	str_append(principal_name, msession->params.protocol);
	str_append_c(principal_name, '@');
	str_append(principal_name, msession->params.host);

	namebuf.length = str_len(principal_name);
	namebuf.value = str_c_modifiable(principal_name);

	major_status = gss_import_name(&minor_status, &namebuf,
				       GSS_C_NT_HOSTBASED_SERVICE,
				       &gsession->gss_principal);
	if (GSS_ERROR(major_status) != 0) {
		*error_r = mech_gssapi_error("importing principal name",
					     major_status, minor_status);
		return DSASL_CLIENT_RESULT_ERR_PROTOCOL;
	}

	e_debug(msession->event, "Successfully imported principal name");

	gsession->out_buf = buffer_create_dynamic(default_pool, 1024);
	gsession->state.gs1 = GSSAPI_GS1_CLIENT_STATE_SEC_CONTEXT;
	return DSASL_CLIENT_RESULT_OK;
}

static int
mech_gssapi_sec_context(struct gssapi_sasl_session *gsession,
			gss_buffer_t in_buf, gss_buffer_t out_buf,
			const char **error_r)
{
	struct dsasl_client_mech_session *msession = &gsession->session;
	OM_uint32 major_status, minor_status;
	OM_uint32 req_flags = GSS_C_REPLAY_FLAG | GSS_C_MUTUAL_FLAG |
			      GSS_C_SEQUENCE_FLAG | GSS_C_INTEG_FLAG;
	gss_OID_desc mech_oid;
	gss_OID ret_mech_oid;

	if (msession->mech == &dsasl_client_mech_gssapi)
		mech_oid = *auth_gssapi_mech_krb5_oid;
	else if (msession->mech == &dsasl_client_mech_gss_spnego)
		mech_oid = *auth_gssapi_mech_spnego_oid;
	else
		i_unreached();

	major_status = gss_init_sec_context(&minor_status, GSS_C_NO_CREDENTIAL,
					    &gsession->gss_ctx,
					    gsession->gss_principal,
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
			(void)gss_release_buffer(&minor_status, out_buf);
			*error_r = "GSSAPI mechanism not Kerberos5";
			return -1;
		}
		e_debug(msession->event,
			"Security context state completed");
		break;
	case GSS_S_CONTINUE_NEEDED:
		e_debug(msession->event,
			"Processed incoming packet correctly, "
			"waiting for another");
		return 0;
	default:
		i_unreached();
	}

	return 1;
}

static enum dsasl_client_result
mech_gssapi_gs1_sec_context(struct gssapi_sasl_session *gsession,
			    gss_buffer_t in_buf, const char **error_r)
{
	OM_uint32 minor_status;
	gss_buffer_desc out_buf;
	int ret;

	ret = mech_gssapi_sec_context(gsession, in_buf, &out_buf, error_r);
	if (ret < 0)
		return DSASL_CLIENT_RESULT_ERR_PROTOCOL;

	buffer_append(gsession->out_buf, out_buf.value, out_buf.length);
	(void)gss_release_buffer(&minor_status, &out_buf);

	if (ret > 0)
		gsession->state.gs1 = GSSAPI_GS1_CLIENT_STATE_UNWRAP;

	return DSASL_CLIENT_RESULT_OK;
}

static enum dsasl_client_result
mech_gssapi_gs1_unwrap(struct gssapi_sasl_session *gsession,
		       gss_buffer_t in_buf, const char **error_r)
{
	struct dsasl_client_mech_session *msession = &gsession->session;
	OM_uint32 major_status, minor_status;
	gss_buffer_desc in_buf_wrap = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc out_buf = GSS_C_EMPTY_BUFFER;
	gss_qop_t qop = GSS_C_QOP_DEFAULT;
	unsigned char *data;
	unsigned int sec_layer = 0;
	buffer_t *buf;
	size_t authzid_size = (msession->authzid == NULL ?
			       0 : strlen(msession->authzid));

	/* Decrypt the inbound challenge and obtain the qop */
	major_status = gss_unwrap(&minor_status, gsession->gss_ctx, in_buf,
				  &out_buf, NULL, &qop);
	if(GSS_ERROR(major_status) != 0) {
		*error_r = mech_gssapi_error(
			"receiving security layer negotiation",
			major_status, minor_status);
		return DSASL_CLIENT_RESULT_ERR_PROTOCOL;
	}

	if (out_buf.length != 4) {
		*error_r = "Bad server message: Invalid security data";
		(void)gss_release_buffer(&minor_status, &out_buf);
		return DSASL_CLIENT_RESULT_ERR_PROTOCOL;
	}

	data = out_buf.value;
	sec_layer = data[0];
	(void)gss_release_buffer(&minor_status, &out_buf);

	/* Check server parameters */
	if((sec_layer & SASL_GSSAPI_QOP_AUTH_ONLY) == 0) {
		*error_r = "Server demands unsupported security parameters";
		return DSASL_CLIENT_RESULT_ERR_PROTOCOL;
	}
	sec_layer = SASL_GSSAPI_QOP_AUTH_ONLY;
	
	buf = t_buffer_create(4 + authzid_size);
	buffer_append_c(buf, sec_layer);
	buffer_append_c(buf, 0);
	buffer_append_c(buf, 0);
	buffer_append_c(buf, 0);
	if (msession->authzid != NULL)
		buffer_append(buf, msession->authzid, authzid_size);

	/* Setup the "authentication data" security buffer */
	in_buf_wrap.value =
		buffer_get_modifiable_data(buf, &in_buf_wrap.length);

	/* Encrypt the data */
	major_status = gss_wrap(&minor_status, gsession->gss_ctx, 0,
				GSS_C_QOP_DEFAULT, &in_buf_wrap, NULL,
				&out_buf);
	if (GSS_ERROR(major_status) != 0) {
		*error_r = mech_gssapi_error(
			"sending security layer negotiation",
			major_status, minor_status);
		return DSASL_CLIENT_RESULT_ERR_INTERNAL;
	}

	e_debug(msession->event, "Negotiated security layer");

	buffer_clear(gsession->out_buf);
	buffer_append(gsession->out_buf, out_buf.value, out_buf.length);
	(void)gss_release_buffer(&minor_status, &out_buf);

	gsession->state.gs1 = GSSAPI_GS1_CLIENT_STATE_WRAP;
	return DSASL_CLIENT_RESULT_OK;
}

static enum dsasl_client_result
mech_gssapi_gs1_auth_input(struct dsasl_client_mech_session *msession,
			   const unsigned char *input, size_t input_len,
			   const char **error_r)
{
	struct gssapi_sasl_session *gsession =
		container_of(msession, struct gssapi_sasl_session, session);
	gss_buffer_desc in_buf;
	enum dsasl_client_result result = DSASL_CLIENT_RESULT_ERR_INTERNAL;

	in_buf.value = (void *)input;
	in_buf.length = input_len;

	switch (gsession->state.gs1) {
	case GSSAPI_GS1_CLIENT_STATE_INIT:
		result = mech_gssapi_gs1_init(gsession, &in_buf, error_r);
		break;
	case GSSAPI_GS1_CLIENT_STATE_SEC_CONTEXT:
		result = mech_gssapi_gs1_sec_context(gsession, &in_buf, error_r);
		break;
	case GSSAPI_GS1_CLIENT_STATE_UNWRAP:
		result = mech_gssapi_gs1_unwrap(gsession, &in_buf, error_r);
		break;
	case GSSAPI_GS1_CLIENT_STATE_WRAP:
	case GSSAPI_GS1_CLIENT_STATE_END:
	default:
		i_unreached();
	}
	return result;
}

static enum dsasl_client_result
mech_gssapi_gs1_auth_output(struct dsasl_client_mech_session *msession,
			    const unsigned char **output_r, size_t *output_len_r,
			    const char **error_r)
{
	struct gssapi_sasl_session *gsession =
		container_of(msession, struct gssapi_sasl_session, session);
	gss_buffer_desc in_buf = GSS_C_EMPTY_BUFFER;
	enum dsasl_client_result result = DSASL_CLIENT_RESULT_ERR_INTERNAL;

	switch (gsession->state.gs1) {
	case GSSAPI_GS1_CLIENT_STATE_INIT:
		result = mech_gssapi_gs1_init(gsession, &in_buf, error_r);
		if (result != DSASL_CLIENT_RESULT_OK)
			return result;
		i_assert(gsession->state.gs1 ==
			 GSSAPI_GS1_CLIENT_STATE_SEC_CONTEXT);
		result = mech_gssapi_gs1_sec_context(gsession, &in_buf, error_r);
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

	*output_r = gsession->out_buf->data;
	*output_len_r = gsession->out_buf->used;
	return DSASL_CLIENT_RESULT_OK;
}

static const struct dsasl_client_mech dsasl_client_mech_gssapi = {
	.name = "GSSAPI",
	.flags = DSASL_MECH_SEC_ALLOW_NULS,

	.auth_new = mech_gssapi_auth_new,
	.auth_free = mech_gssapi_auth_free,
	.auth_check = mech_gssapi_auth_check,
	.auth_input = mech_gssapi_gs1_auth_input,
	.auth_output = mech_gssapi_gs1_auth_output,
};

static const struct dsasl_client_mech dsasl_client_mech_gss_spnego = {
	.name = "GSS-SPNEGO",
	.flags = DSASL_MECH_SEC_ALLOW_NULS,

	.auth_new = mech_gssapi_auth_new,
	.auth_free = mech_gssapi_auth_free,
	.auth_check = mech_gssapi_auth_check,
	.auth_input = mech_gssapi_gs1_auth_input,
	.auth_output = mech_gssapi_gs1_auth_output,
};

void dsasl_client_init_gssapi(struct dsasl_client *client)
{
	dsasl_client_mech_register(client, &dsasl_client_mech_gssapi);
	dsasl_client_mech_register(client, &dsasl_client_mech_gss_spnego);
}
