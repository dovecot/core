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
	gss_cred_id_t gss_cred;
	gss_ctx_id_t gss_ctx;
	struct gss_channel_bindings_struct gss_cbind;
	bool have_cbind;

	buffer_t *out_buf;
};

#ifdef HAVE_GSS_SET_CRED_OPTION
#ifndef HAVE_GSS_KRB5_CRED_NO_CI_FLAGS_X
/* 1.2.752.43.13.29, the OID of GSS_KRB5_CRED_NO_CI_FLAGS_X */
static gss_OID_desc no_ci_flags_oid_desc = {
	6, (void *)"\x2a\x85\x70\x2b\x0d\x1d"
};
static const gss_OID GSS_KRB5_CRED_NO_CI_FLAGS_X = &no_ci_flags_oid_desc;
#endif
#endif

/* RFC 5056 section 2.1: channel bindings start with the type and a colon */
#define GSSAPI_CBIND_PREFIX SSL_CHANNEL_BIND_TYPE_TLS_SERVER_END_POINT ":"

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
	if (gsession->gss_cred != GSS_C_NO_CREDENTIAL)
		(void)gss_release_cred(&minor_status, &gsession->gss_cred);
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
#ifndef HAVE_GSS_SET_NEG_MECHS
	if (msession->mech == &dsasl_client_mech_gss_spnego) {
		*error_r = "GSS-SPNEGO can't be restricted to Kerberos "
			"(gss_set_neg_mechs() not available in the GSSAPI library)";
		return -1;
	}
#endif
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

static int
mech_gssapi_init_channel_binding(struct gssapi_sasl_session *gsession,
				 const char **error_r)
{
	struct dsasl_client_mech_session *msession = &gsession->session;
	const size_t prefix_len = strlen(GSSAPI_CBIND_PREFIX);
	const buffer_t *cbind_data;
	const char *error;
	unsigned char *app_data;

	/* Without TLS there is nothing to bind to. */
	if (!dsasl_client_session_channel_binding_available(msession))
		return 0;
	/* The server may enforce the binding. Continuing without it would let
	   a man in the middle with a certificate that has no binding relay the
	   authentication to the server. */
	if (dsasl_client_session_get_channel_binding(
			msession, SSL_CHANNEL_BIND_TYPE_TLS_SERVER_END_POINT,
			&cbind_data, &error) < 0) {
		*error_r = t_strdup_printf(
			"Failed to get the TLS channel binding: %s", error);
		return -1;
	}

	app_data = p_malloc(msession->pool, prefix_len + cbind_data->used);
	memcpy(app_data, GSSAPI_CBIND_PREFIX, prefix_len);
	memcpy(app_data + prefix_len, cbind_data->data, cbind_data->used);
	gsession->gss_cbind.application_data.value = app_data;
	gsession->gss_cbind.application_data.length =
		prefix_len + cbind_data->used;
	gsession->have_cbind = TRUE;
	return 0;
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
	gsession->gss_cred = GSS_C_NO_CREDENTIAL;
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

	if (mech_gssapi_init_channel_binding(gsession, error_r) < 0)
		return DSASL_CLIENT_RESULT_ERR_PROTOCOL;

	gsession->out_buf = buffer_create_dynamic(default_pool, 1024);
	gsession->state.gs1 = GSSAPI_GS1_CLIENT_STATE_SEC_CONTEXT;
	return DSASL_CLIENT_RESULT_OK;
}

static int
mech_gssapi_spnego_cred(struct gssapi_sasl_session *gsession,
			const char **error_r)
{
	OM_uint32 major_status, minor_status;
	gss_OID_set_desc mechs;

	mechs.count = 1;
	mechs.elements = (gss_OID)auth_gssapi_mech_spnego_oid;
	major_status = gss_acquire_cred(&minor_status, GSS_C_NO_NAME,
					0, &mechs,
					GSS_C_INITIATE, &gsession->gss_cred,
					NULL, NULL);
	if (GSS_ERROR(major_status) != 0) {
		gsession->gss_cred = GSS_C_NO_CREDENTIAL;
		*error_r = mech_gssapi_error(
			"acquiring the initiator credential",
			major_status, minor_status);
		return -1;
	}

	/* Without this the server could pick any mechanism that SPNEGO
	   supports, such as NTLM, and get a token for it before the mechanism
	   is checked. */
#ifdef HAVE_GSS_SET_NEG_MECHS
	gss_OID_set_desc neg_mechs;

	neg_mechs.count = 1;
	neg_mechs.elements = (gss_OID)auth_gssapi_mech_krb5_oid;
	major_status = gss_set_neg_mechs(&minor_status, gsession->gss_cred,
					 &neg_mechs);
	if (GSS_ERROR(major_status) != 0) {
		*error_r = mech_gssapi_error(
			"restricting the negotiation to Kerberos",
			major_status, minor_status);
		return -1;
	}
#endif

#ifdef HAVE_GSS_SET_CRED_OPTION
	gss_buffer_desc empty = GSS_C_EMPTY_BUFFER;

	/* Kerberos sets the integrity and confidentiality flags, which would
	   make the server start a security layer after GSS-SPNEGO. If this
	   isn't supported, the flags returned for the context tell whether
	   there is a security layer. */
	major_status = gss_set_cred_option(&minor_status, &gsession->gss_cred,
					   GSS_KRB5_CRED_NO_CI_FLAGS_X,
					   &empty);
	if (GSS_ERROR(major_status) != 0) {
		e_debug(gsession->session.event, "%s", mech_gssapi_error(
			"setting the credential option",
			major_status, minor_status));
	}
#endif
	return 0;
}

static int
mech_gssapi_sec_context(struct gssapi_sasl_session *gsession,
			gss_buffer_t in_buf, gss_buffer_t out_buf,
			const char **error_r)
{
	struct dsasl_client_mech_session *msession = &gsession->session;
	OM_uint32 major_status, minor_status;
	OM_uint32 req_flags = GSS_C_REPLAY_FLAG | GSS_C_MUTUAL_FLAG |
			      GSS_C_SEQUENCE_FLAG;
	OM_uint32 ret_flags = 0;
	gss_OID_desc mech_oid;
	gss_OID ret_mech_oid = GSS_C_NO_OID;

	if (msession->mech == &dsasl_client_mech_gssapi) {
		mech_oid = *auth_gssapi_mech_krb5_oid;
		req_flags |= GSS_C_INTEG_FLAG;
	} else if (msession->mech == &dsasl_client_mech_gss_spnego) {
		mech_oid = *auth_gssapi_mech_spnego_oid;
		if (gsession->gss_ctx == GSS_C_NO_CONTEXT &&
		    gsession->gss_cred == GSS_C_NO_CREDENTIAL &&
		    mech_gssapi_spnego_cred(gsession, error_r) < 0)
			return -1;
	} else {
		i_unreached();
	}

	major_status = gss_init_sec_context(&minor_status, gsession->gss_cred,
					    &gsession->gss_ctx,
					    gsession->gss_principal,
					    &mech_oid, req_flags,
					    0, (gsession->have_cbind ?
						&gsession->gss_cbind :
						GSS_C_NO_CHANNEL_BINDINGS),
					    in_buf, &ret_mech_oid, out_buf,
					    &ret_flags, NULL);
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
		if (ret_mech_oid == GSS_C_NO_OID ||
		    !auth_gssapi_oid_equal(ret_mech_oid,
					   auth_gssapi_mech_krb5_oid)) {
			(void)gss_release_buffer(&minor_status, out_buf);
			*error_r = "GSSAPI mechanism not Kerberos5";
			return -1;
		}
		if (msession->mech == &dsasl_client_mech_gss_spnego) {
			/* Without a security layer exchange, the mutual
			   authentication is the only proof of the server. */
			if ((ret_flags & GSS_C_MUTUAL_FLAG) == 0) {
				(void)gss_release_buffer(&minor_status, out_buf);
				*error_r = "GSS-SPNEGO server was not authenticated";
				return -1;
			}
			if ((ret_flags & (GSS_C_INTEG_FLAG |
					  GSS_C_CONF_FLAG)) != 0) {
				(void)gss_release_buffer(&minor_status, out_buf);
#ifdef HAVE_GSS_SET_CRED_OPTION
				*error_r = "GSS-SPNEGO security layer is not supported";
#else
				*error_r = "GSS-SPNEGO security layer is not supported "
					"(gss_set_cred_option() not available "
					"in the GSSAPI library)";
#endif
				return -1;
			}
		}
		e_debug(msession->event,
			"Security context state completed");
		break;
	case GSS_S_CONTINUE_NEEDED:
		/* Don't give the server a chance to get a token for another
		   mechanism. SPNEGO is the mechanism until it is selected. */
		if (ret_mech_oid != GSS_C_NO_OID &&
		    !auth_gssapi_oid_equal(ret_mech_oid,
					   auth_gssapi_mech_krb5_oid) &&
		    (msession->mech != &dsasl_client_mech_gss_spnego ||
		     !auth_gssapi_oid_equal(ret_mech_oid,
					    auth_gssapi_mech_spnego_oid))) {
			(void)gss_release_buffer(&minor_status, out_buf);
			*error_r = "GSSAPI mechanism not Kerberos5";
			return -1;
		}
		e_debug(msession->event,
			"Processed incoming packet correctly, "
			"waiting for another");
		return 0;
	default:
		(void)gss_release_buffer(&minor_status, out_buf);
		*error_r = mech_gssapi_error("processing incoming data",
					     major_status, minor_status);
		return -1;
	}

	return 1;
}

static enum dsasl_client_result
mech_gssapi_gs1_sec_context(struct gssapi_sasl_session *gsession,
			    gss_buffer_t in_buf, const char **error_r)
{
	OM_uint32 minor_status;
	gss_buffer_desc out_buf = GSS_C_EMPTY_BUFFER;
	int ret;

	ret = mech_gssapi_sec_context(gsession, in_buf, &out_buf, error_r);
	if (ret < 0)
		return DSASL_CLIENT_RESULT_ERR_PROTOCOL;

	/* The last step may have no token, and the previous one is not sent
	   again. */
	buffer_clear(gsession->out_buf);
	buffer_append(gsession->out_buf, out_buf.value, out_buf.length);
	(void)gss_release_buffer(&minor_status, &out_buf);

	if (ret > 0) {
		/* GSS-SPNEGO has no security layer negotiation. */
		if (gsession->session.mech == &dsasl_client_mech_gss_spnego)
			gsession->state.gs1 = GSSAPI_GS1_CLIENT_STATE_END;
		else
			gsession->state.gs1 = GSSAPI_GS1_CLIENT_STATE_UNWRAP;
	}

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
		*error_r = "Server sent unexpected data";
		return DSASL_CLIENT_RESULT_ERR_PROTOCOL;
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
	case GSSAPI_GS1_CLIENT_STATE_END:
		break;
	}

	*output_r = gsession->out_buf->data;
	*output_len_r = gsession->out_buf->used;
	return DSASL_CLIENT_RESULT_OK;
}

static const struct dsasl_client_mech dsasl_client_mech_gssapi = {
	.name = "GSSAPI",
	.flags = DSASL_MECH_SEC_ALLOW_NULS | DSASL_MECH_SEC_NO_PASSWORD,

	.auth_new = mech_gssapi_auth_new,
	.auth_free = mech_gssapi_auth_free,
	.auth_check = mech_gssapi_auth_check,
	.auth_input = mech_gssapi_gs1_auth_input,
	.auth_output = mech_gssapi_gs1_auth_output,
};

static const struct dsasl_client_mech dsasl_client_mech_gss_spnego = {
	.name = "GSS-SPNEGO",
	.flags = DSASL_MECH_SEC_ALLOW_NULS | DSASL_MECH_SEC_NO_PASSWORD,

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
