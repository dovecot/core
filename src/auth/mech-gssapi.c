/*
 * GSSAPI Module
 *
 * Copyright (c) 2005 Jelmer Vernooij <jelmer@samba.org>
 *
 * Related standards:
 * - draft-ietf-sasl-gssapi-03 
 * - RFC2222
 *
 * Some parts inspired by an older patch from Colin Walters
 *
 * This software is released under the MIT license.
 */

#include "auth-common.h"
#include "env-util.h"
#include "str.h"
#include "str-sanitize.h"
#include "hex-binary.h"
#include "safe-memset.h"
#include "mech.h"
#include "passdb.h"

#include <stdlib.h>

#if defined(BUILTIN_GSSAPI) || defined(PLUGIN_BUILD)

#ifndef HAVE___GSS_USEROK
#  define USE_KRB5_USEROK
#  include <krb5.h>
#endif

#ifdef HAVE_GSSAPI_GSSAPI_H
#  include <gssapi/gssapi.h>
#elif defined (HAVE_GSSAPI_H)
#  include <gssapi.h>
#endif

#ifdef HAVE_GSSAPI_GSSAPI_KRB5_H
#  include <gssapi/gssapi_krb5.h>
#elif defined (HAVE_GSSAPI_KRB5_H)
#  include <gssapi_krb5.h>
#else
#  undef USE_KRB5_USEROK
#endif

#ifdef HAVE_GSSAPI_GSSAPI_EXT_H
#  include <gssapi/gssapi_ext.h>
#endif

/* Non-zero flags defined in RFC 2222 */
enum sasl_gssapi_qop {
	SASL_GSSAPI_QOP_UNSPECIFIED = 0x00,
	SASL_GSSAPI_QOP_AUTH_ONLY   = 0x01,
	SASL_GSSAPI_QOP_AUTH_INT    = 0x02,
	SASL_GSSAPI_QOP_AUTH_CONF   = 0x04
};

struct gssapi_auth_request {
	struct auth_request auth_request;
	gss_ctx_id_t gss_ctx;
	gss_cred_id_t service_cred;

	enum { 
		GSS_STATE_SEC_CONTEXT, 
		GSS_STATE_WRAP, 
		GSS_STATE_UNWRAP
	} sasl_gssapi_state;

	gss_name_t authn_name;
	gss_name_t authz_name;
		
	pool_t pool;
};

static bool gssapi_initialized = FALSE;

static void auth_request_log_gss_error(struct auth_request *request,
				       OM_uint32 status_value, int status_type,
				       const char *description)
{
	OM_uint32 message_context = 0;
	OM_uint32 major_status, minor_status;
	gss_buffer_desc status_string;

	do {
		major_status = gss_display_status(&minor_status, status_value, 
						  status_type, GSS_C_NO_OID,
						  &message_context,
						  &status_string);
	
		auth_request_log_error(request, "gssapi",
			"While %s: %s", description,
			str_sanitize(status_string.value, (size_t)-1));

		major_status = gss_release_buffer(&minor_status,
						  &status_string);
	} while (message_context != 0);
}

static void mech_gssapi_initialize(struct auth *auth)
{
	const char *path = auth->set->krb5_keytab;

	if (*path != '\0') {
		/* environment may be used by Kerberos 5 library directly */
		env_put(t_strconcat("KRB5_KTNAME=", path, NULL));
#ifdef HAVE_GSSKRB5_REGISTER_ACCEPTOR_IDENTITY
		gsskrb5_register_acceptor_identity(path);
#elif defined (HAVE_KRB5_GSS_REGISTER_ACCEPTOR_IDENTITY)
		krb5_gss_register_acceptor_identity(path);
#endif
	}
}

static struct auth_request *mech_gssapi_auth_new(void)
{
	struct gssapi_auth_request *request;
	pool_t pool;

	pool = pool_alloconly_create("gssapi_auth_request", 1024);
	request = p_new(pool, struct gssapi_auth_request, 1);
	request->pool = pool;

	request->gss_ctx = GSS_C_NO_CONTEXT;

	request->auth_request.pool = pool;
	return &request->auth_request;
}

static OM_uint32 obtain_service_credentials(struct auth_request *request,
					    gss_cred_id_t *ret)
{
	OM_uint32 major_status, minor_status;
	string_t *principal_name;
	gss_buffer_desc inbuf;
	gss_name_t gss_principal;
	const char *service_name;

	if (!gssapi_initialized) {
		gssapi_initialized = TRUE;
		mech_gssapi_initialize(request->auth);
	}

	if (strcmp(request->auth->set->gssapi_hostname, "$ALL") == 0) {
		auth_request_log_info(request, "gssapi",
				      "Using all keytab entries");
		*ret = GSS_C_NO_CREDENTIAL;
		return GSS_S_COMPLETE;
	}

	if (strcasecmp(request->service, "POP3") == 0) {
		/* The standard POP3 service name with GSSAPI is called
		   just "pop". */
		service_name = "pop";
	} else {
		service_name = t_str_lcase(request->service);
	}

	principal_name = t_str_new(128);
	str_append(principal_name, service_name);
	str_append_c(principal_name, '@');
	str_append(principal_name, request->auth->set->gssapi_hostname);

	auth_request_log_info(request, "gssapi",
		"Obtaining credentials for %s", str_c(principal_name));

	inbuf.length = str_len(principal_name);
	inbuf.value = str_c_modifiable(principal_name);

	major_status = gss_import_name(&minor_status, &inbuf, 
				       GSS_C_NT_HOSTBASED_SERVICE,
				       &gss_principal);

	str_free(&principal_name);

	if (GSS_ERROR(major_status)) {
		auth_request_log_gss_error(request, major_status,
					   GSS_C_GSS_CODE,
					   "importing principal name");
		return major_status;
	}

	major_status = gss_acquire_cred(&minor_status, gss_principal, 0, 
					GSS_C_NULL_OID_SET, GSS_C_ACCEPT,
					ret, NULL, NULL);

	if (GSS_ERROR(major_status)) {
		auth_request_log_gss_error(request, major_status,
					   GSS_C_GSS_CODE,
					   "acquiring service credentials");
		auth_request_log_gss_error(request, minor_status,
					   GSS_C_MECH_CODE,
					   "acquiring service credentials");
		return major_status;
	}

	gss_release_name(&minor_status, &gss_principal);

	return major_status;
}

#ifndef HAVE___GSS_USEROK
static gss_name_t
import_name(struct auth_request *request, void *str, size_t len)
{
	OM_uint32 major_status, minor_status;
	gss_buffer_desc name_buf;
	gss_name_t name;

	name_buf.value = str;
	name_buf.length = len;
	major_status = gss_import_name(&minor_status,
				       &name_buf,
				       GSS_C_NO_OID,
				       &name);
	if (GSS_ERROR(major_status)) {
		auth_request_log_gss_error(request, major_status,
					   GSS_C_GSS_CODE, "gss_import_name");
		return GSS_C_NO_NAME;
	}

	return name;
}
#endif

static void gssapi_sec_context(struct gssapi_auth_request *request,
			       gss_buffer_desc inbuf)
{
	OM_uint32 major_status, minor_status;
	gss_buffer_desc outbuf;

	major_status = gss_accept_sec_context (
		&minor_status,
		&request->gss_ctx,
		request->service_cred,
		&inbuf,
		GSS_C_NO_CHANNEL_BINDINGS,
		&request->authn_name, 
		NULL, /* mech_type */
		&outbuf,
		NULL, /* ret_flags */
		NULL, /* time_rec */
		NULL  /* delegated_cred_handle */
	);
	
	if (GSS_ERROR(major_status)) {
		auth_request_log_gss_error(&request->auth_request, major_status,
					   GSS_C_GSS_CODE,
					   "processing incoming data");
		auth_request_log_gss_error(&request->auth_request, minor_status,
					   GSS_C_MECH_CODE,
					   "processing incoming data");

		auth_request_fail(&request->auth_request);
		return;
	} 

	if (major_status == GSS_S_COMPLETE) {
		request->sasl_gssapi_state = GSS_STATE_WRAP;
		auth_request_log_info(&request->auth_request, "gssapi", 
				      "security context state completed.");
	} else {
		auth_request_log_info(&request->auth_request, "gssapi", 
				      "Processed incoming packet correctly, "
				      "waiting for another.");
	}

	request->auth_request.callback(&request->auth_request,
				       AUTH_CLIENT_RESULT_CONTINUE,
				       outbuf.value, outbuf.length);

	major_status = gss_release_buffer(&minor_status, &outbuf);
}

static void gssapi_wrap(struct gssapi_auth_request *request,
			gss_buffer_desc inbuf)
{
	OM_uint32 major_status, minor_status;
	gss_buffer_desc outbuf;
	unsigned char ret[4];

	/* The clients return data should be empty here */
	
	/* Only authentication, no integrity or confidentiality
	   protection (yet?) */
	ret[0] = (SASL_GSSAPI_QOP_UNSPECIFIED |
                  SASL_GSSAPI_QOP_AUTH_ONLY);
	ret[1] = 0xFF;
	ret[2] = 0xFF;
	ret[3] = 0xFF;

	inbuf.length = 4;
	inbuf.value = ret;
	
	major_status = gss_wrap(&minor_status, request->gss_ctx, 0,
				GSS_C_QOP_DEFAULT, &inbuf, NULL, &outbuf);

	if (GSS_ERROR(major_status)) {
		auth_request_log_gss_error(&request->auth_request, major_status,
			GSS_C_GSS_CODE, "sending security layer negotiation");
		auth_request_log_gss_error(&request->auth_request, minor_status,
			GSS_C_MECH_CODE, "sending security layer negotiation");
		auth_request_fail(&request->auth_request);
		return;
	} 

	auth_request_log_info(&request->auth_request, "gssapi", 
			      "Negotiated security layer");

	request->auth_request.callback(&request->auth_request,
				       AUTH_CLIENT_RESULT_CONTINUE,
				       outbuf.value, outbuf.length);

	major_status = gss_release_buffer(&minor_status, &outbuf);

	request->sasl_gssapi_state = GSS_STATE_UNWRAP;
}

#ifdef USE_KRB5_USEROK
static bool
gssapi_krb5_userok(struct gssapi_auth_request *request, gss_name_t name,
		   bool check_name_type)
{
	krb5_context ctx;
	krb5_principal princ;
	krb5_error_code krb5_err;
	OM_uint32 major_status, minor_status;
	gss_buffer_desc princ_name;
	gss_OID name_type;
	const char *princ_display_name;
	bool ret = FALSE;

	/* Parse out the principal's username */
	major_status = gss_display_name(&minor_status, name,
					&princ_name, &name_type);
	if (major_status != GSS_S_COMPLETE) {
		auth_request_log_gss_error(&request->auth_request, major_status,
					   GSS_C_GSS_CODE,
					   "gssapi_krb5_userok");
		return FALSE;
	}
	if (name_type != GSS_KRB5_NT_PRINCIPAL_NAME && check_name_type) {
		auth_request_log_error(&request->auth_request, "gssapi",
				       "OID not kerberos principal name");
		return FALSE;
	}
	princ_display_name = t_strndup(princ_name.value, princ_name.length);
	gss_release_buffer(&minor_status, &princ_name);

	/* Init a krb5 context and parse the principal username */
	krb5_err = krb5_init_context(&ctx);
	if (krb5_err != 0) {
		auth_request_log_error(&request->auth_request, "gssapi",
			"krb5_init_context() failed: %d", (int)krb5_err);
		return FALSE;
	}
	krb5_err = krb5_parse_name(ctx, princ_display_name, &princ);
	if (krb5_err != 0) {
		/* writing the error string would be better, but we probably
		   rarely get here and there doesn't seem to be a standard
		   way of getting it */
		auth_request_log_error(&request->auth_request, "gssapi",
				       "krb5_parse_name() failed: %d",
				       (int)krb5_err);
	} else {
		/* See if the principal is authorized to act as the
		   specified user */
		ret = krb5_kuserok(ctx, princ, request->auth_request.user);
		krb5_free_principal(ctx, princ);
	}
	krb5_free_context(ctx);
	return ret;
}
#endif

static void gssapi_unwrap(struct gssapi_auth_request *request,
			  gss_buffer_desc inbuf)
{
	OM_uint32 major_status, minor_status;
	gss_buffer_desc outbuf;
#if defined(HAVE___GSS_USEROK) || !defined(USE_KRB5_USEROK)
	int equal_authn_authz = 0;
#endif
	major_status = gss_unwrap(&minor_status, request->gss_ctx, 
				  &inbuf, &outbuf, NULL, NULL);

	if (GSS_ERROR(major_status)) {
		auth_request_log_gss_error(&request->auth_request, major_status,
					   GSS_C_GSS_CODE,
					   "final negotiation: gss_unwrap");
		auth_request_fail(&request->auth_request);
		return;
	} 

	if (outbuf.length <= 4) {
		auth_request_log_error(&request->auth_request, "gssapi",
				       "Invalid response length");
		auth_request_fail(&request->auth_request);
		return;
	}

#ifdef HAVE___GSS_USEROK
	/* Solaris __gss_userok() correctly handles cross-realm
	   authentication. */
	request->auth_request.user =
		p_strndup(request->auth_request.pool,
			  (unsigned char *)outbuf.value + 4,
			  outbuf.length - 4);

	major_status = __gss_userok(&minor_status, request->authn_name,
				    request->auth_request.user,
				    &equal_authn_authz);
	if (GSS_ERROR(major_status)) {
		auth_request_log_gss_error(&request->auth_request, major_status,
					   GSS_C_GSS_CODE,
					   "__gss_userok failed");
		auth_request_fail(&request->auth_request);
		return;
	} 

	if (equal_authn_authz == 0) {
		auth_request_log_error(&request->auth_request, "gssapi",
				       "credentials not valid");

		auth_request_fail(&request->auth_request);
		return;
	}
#else
	request->authz_name = import_name(&request->auth_request,
					  (unsigned char *)outbuf.value + 4,
					  outbuf.length - 4);
	if ((request->authn_name == GSS_C_NO_NAME) ||
	    (request->authz_name == GSS_C_NO_NAME)) {
		/* XXX (pod): is this check necessary? */
		auth_request_log_error(&request->auth_request, "gssapi",
			"one of authn_name or authz_name not determined");
		auth_request_fail(&request->auth_request);
		return;
	}

	request->auth_request.user =
		p_strndup(request->auth_request.pool,
			  (unsigned char *)outbuf.value + 4,
			  outbuf.length - 4);

#ifdef USE_KRB5_USEROK
	if (!gssapi_krb5_userok(request, request->authn_name, TRUE)) {
		auth_request_log_error(&request->auth_request, "gssapi",
			"authn_name not authorized");
		auth_request_fail(&request->auth_request);
		return;
	}
	
	if (!gssapi_krb5_userok(request, request->authz_name, FALSE)) {
		auth_request_log_error(&request->auth_request, "gssapi",
			"authz_name not authorized");
		auth_request_fail(&request->auth_request);
		return;
	}
#else
	major_status = gss_compare_name(&minor_status,
					request->authn_name,
					request->authz_name,
					&equal_authn_authz);
	if (equal_authn_authz == 0) {
		auth_request_log_error(&request->auth_request, "gssapi",
			"authn_name and authz_name differ: not supported");
		auth_request_fail(&request->auth_request);
		return;
	}
#endif
#endif
	auth_request_success(&request->auth_request, NULL, 0);
}

static void
mech_gssapi_auth_continue(struct auth_request *request,
			  const unsigned char *data, size_t data_size)
{
	struct gssapi_auth_request *gssapi_request = 
		(struct gssapi_auth_request *)request;
	gss_buffer_desc inbuf;

	inbuf.value = (void *)data;
	inbuf.length = data_size;

	switch (gssapi_request->sasl_gssapi_state) {
	case GSS_STATE_SEC_CONTEXT:
		gssapi_sec_context(gssapi_request, inbuf);
		break;
	case GSS_STATE_WRAP:
		gssapi_wrap(gssapi_request, inbuf);
		break;
	case GSS_STATE_UNWRAP:
		gssapi_unwrap(gssapi_request, inbuf);
		break;
	} 
}

static void
mech_gssapi_auth_initial(struct auth_request *request,
		       const unsigned char *data, size_t data_size)
{
	OM_uint32 major_status;
	struct gssapi_auth_request *gssapi_request = 
		(struct gssapi_auth_request *)request;
	
	major_status =
		obtain_service_credentials(request,
					   &gssapi_request->service_cred);

	if (GSS_ERROR(major_status)) {
		auth_request_internal_failure(request);
		return;
	}
	gssapi_request->authn_name = GSS_C_NO_NAME;
	gssapi_request->authz_name = GSS_C_NO_NAME;

	gssapi_request->sasl_gssapi_state = GSS_STATE_SEC_CONTEXT;

	if (data_size == 0) {
		/* The client should go first */
		request->callback(request, AUTH_CLIENT_RESULT_CONTINUE,
				  NULL, 0);
	} else {
		mech_gssapi_auth_continue(request, data, data_size);
	}
}


static void
mech_gssapi_auth_free(struct auth_request *request)
{
	OM_uint32 major_status, minor_status;
	struct gssapi_auth_request *gssapi_request = 
		(struct gssapi_auth_request *)request;

	if (gssapi_request->gss_ctx != GSS_C_NO_CONTEXT) {
		major_status = gss_delete_sec_context(&minor_status,
						      &gssapi_request->gss_ctx,
						      GSS_C_NO_BUFFER);
	}

	major_status = gss_release_cred(&minor_status,
					&gssapi_request->service_cred);
	if (gssapi_request->authn_name != GSS_C_NO_NAME) {
		major_status = gss_release_name(&minor_status,
						&gssapi_request->authn_name);
	}
	if (gssapi_request->authz_name != GSS_C_NO_NAME) {
		major_status = gss_release_name(&minor_status,
						&gssapi_request->authz_name);
	}
	pool_unref(&request->pool);
}

const struct mech_module mech_gssapi = {
	"GSSAPI",

	MEMBER(flags) 0,
	MEMBER(passdb_need) MECH_PASSDB_NEED_NOTHING,

	mech_gssapi_auth_new,
	mech_gssapi_auth_initial,
	mech_gssapi_auth_continue,
	mech_gssapi_auth_free
};

/* MTI Kerberos v1.5+ and Heimdal v0.7+ supports SPNEGO for Kerberos tickets
   internally. Nothing else needs to be done here. Note however that this does
   not support SPNEGO when the only available credential is NTLM.. */
const struct mech_module mech_gssapi_spnego = {
	"GSS-SPNEGO",

	MEMBER(flags) 0,
	MEMBER(passdb_need) MECH_PASSDB_NEED_NOTHING,

	mech_gssapi_auth_new,
        mech_gssapi_auth_initial,
        mech_gssapi_auth_continue,
        mech_gssapi_auth_free
};

#ifndef BUILTIN_GSSAPI
void mech_gssapi_init(void);
void mech_gssapi_deinit(void);

void mech_gssapi_init(void)
{
	mech_register_module(&mech_gssapi);
#ifdef HAVE_GSSAPI_SPNEGO
	/* load if we already didn't load it using winbind */
	if (mech_module_find(mech_gssapi_spnego.name) == NULL)
		mech_register_module(&mech_gssapi_spnego);
#endif
}

void mech_gssapi_deinit(void)
{
#ifdef HAVE_GSSAPI_SPNEGO
	struct mech_module *mech;

	mech = mech_module_find(mech_gssapi_spnego.name);
	if (mech != NULL && mech.auth_new == mech_gssapi_auth_new)
		mech_unregister_module(&mech_gssapi_spnego);
#endif
	mech_unregister_module(&mech_gssapi);
}
#endif

#endif
