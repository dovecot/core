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

#define krb5_boolean2bool(X) ((X) != 0)

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

static gss_OID_desc mech_gssapi_krb5_oid =
	{ 9, "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02" };

static int
mech_gssapi_wrap(struct gssapi_auth_request *request, gss_buffer_desc inbuf);

static void mech_gssapi_log_error(struct auth_request *request,
				  OM_uint32 status_value, int status_type,
				  const char *description)
{
	OM_uint32 message_context = 0;
	OM_uint32 minor_status;
	gss_buffer_desc status_string;

	do {
		(void)gss_display_status(&minor_status, status_value,
					 status_type, GSS_C_NO_OID,
					 &message_context, &status_string);

		e_info(request->mech_event,
		       "While %s: %s", description,
		       str_sanitize(status_string.value, (size_t)-1));

		(void)gss_release_buffer(&minor_status, &status_string);
	} while (message_context != 0);
}

static void mech_gssapi_initialize(const struct auth_settings *set)
{
	const char *path = set->krb5_keytab;

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

	pool = pool_alloconly_create(MEMPOOL_GROWING"gssapi_auth_request", 2048);
	request = p_new(pool, struct gssapi_auth_request, 1);
	request->pool = pool;

	request->gss_ctx = GSS_C_NO_CONTEXT;

	request->auth_request.pool = pool;
	return &request->auth_request;
}

static OM_uint32
obtain_service_credentials(struct auth_request *request, gss_cred_id_t *ret_r)
{
	OM_uint32 major_status, minor_status;
	string_t *principal_name;
	gss_buffer_desc inbuf;
	gss_name_t gss_principal;
	const char *service_name;

	if (!gssapi_initialized) {
		gssapi_initialized = TRUE;
		mech_gssapi_initialize(request->set);
	}

	if (strcmp(request->set->gssapi_hostname, "$ALL") == 0) {
		e_debug(request->mech_event,
			"Using all keytab entries");
		*ret_r = GSS_C_NO_CREDENTIAL;
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
	str_append(principal_name, request->set->gssapi_hostname);

	e_debug(request->mech_event,
		"Obtaining credentials for %s", str_c(principal_name));

	inbuf.length = str_len(principal_name);
	inbuf.value = str_c_modifiable(principal_name);

	major_status = gss_import_name(&minor_status, &inbuf, 
				       GSS_C_NT_HOSTBASED_SERVICE,
				       &gss_principal);
	str_free(&principal_name);

	if (GSS_ERROR(major_status) != 0) {
		mech_gssapi_log_error(request, major_status, GSS_C_GSS_CODE,
				      "importing principal name");
		return major_status;
	}

	major_status = gss_acquire_cred(&minor_status, gss_principal, 0, 
					GSS_C_NULL_OID_SET, GSS_C_ACCEPT,
					ret_r, NULL, NULL);
	if (GSS_ERROR(major_status) != 0) {
		mech_gssapi_log_error(request, major_status, GSS_C_GSS_CODE,
				      "acquiring service credentials");
		mech_gssapi_log_error(request, minor_status, GSS_C_MECH_CODE,
				      "acquiring service credentials");
		return major_status;
	}

	gss_release_name(&minor_status, &gss_principal);
	return major_status;
}

static gss_name_t
import_name(struct auth_request *request, void *str, size_t len)
{
	OM_uint32 major_status, minor_status;
	gss_buffer_desc name_buf;
	gss_name_t name;

	name_buf.value = str;
	name_buf.length = len;
	major_status = gss_import_name(&minor_status, &name_buf,
				       GSS_C_NO_OID, &name);
	if (GSS_ERROR(major_status) != 0) {
		mech_gssapi_log_error(request, major_status, GSS_C_GSS_CODE,
				      "gss_import_name");
		return GSS_C_NO_NAME;
	}
	return name;
}

static gss_name_t
duplicate_name(struct auth_request *request, gss_name_t old)
{
	OM_uint32 major_status, minor_status;
	gss_name_t new;

	major_status = gss_duplicate_name(&minor_status, old, &new);
	if (GSS_ERROR(major_status) != 0) {
		mech_gssapi_log_error(request, major_status, GSS_C_GSS_CODE,
				      "gss_duplicate_name");
		return GSS_C_NO_NAME;
	}
	return new;
}

static bool data_has_nuls(const void *data, size_t len)
{
	const unsigned char *c = data;
	size_t i;

	/* apparently all names end with NUL? */
	if (len > 0 && c[len-1] == '\0')
		len--;

	for (i = 0; i < len; i++) {
		if (c[i] == '\0')
			return TRUE;
	}
	return FALSE;
}

static int get_display_name(struct auth_request *auth_request, gss_name_t name,
			    gss_OID *name_type_r, const char **display_name_r)
{
	OM_uint32 major_status, minor_status;
	gss_buffer_desc buf;

	major_status = gss_display_name(&minor_status, name,
					&buf, name_type_r);
	if (major_status != GSS_S_COMPLETE) {
		mech_gssapi_log_error(auth_request, major_status,
				      GSS_C_GSS_CODE, "gss_display_name");
		return -1;
	}
	if (data_has_nuls(buf.value, buf.length)) {
		e_info(auth_request->mech_event,
		       "authn_name has NULs");
		return -1;
	}
	*display_name_r = t_strndup(buf.value, buf.length);
	(void)gss_release_buffer(&minor_status, &buf);
	return 0;
}

static bool mech_gssapi_oid_cmp(const gss_OID_desc *oid1,
				const gss_OID_desc *oid2)
{
	return oid1->length == oid2->length &&
		mem_equals_timing_safe(oid1->elements, oid2->elements, oid1->length);
}

static int
mech_gssapi_sec_context(struct gssapi_auth_request *request,
			gss_buffer_desc inbuf)
{
	struct auth_request *auth_request = &request->auth_request;
	OM_uint32 major_status, minor_status;
	gss_buffer_desc output_token;
	gss_OID name_type;
	gss_OID mech_type;
	const char *username, *error;
	int ret = 0;

	major_status = gss_accept_sec_context (
		&minor_status,
		&request->gss_ctx,
		request->service_cred,
		&inbuf,
		GSS_C_NO_CHANNEL_BINDINGS,
		&request->authn_name, 
		&mech_type,
		&output_token,
		NULL, /* ret_flags */
		NULL, /* time_rec */
		NULL  /* delegated_cred_handle */
	);

	if (GSS_ERROR(major_status) != 0) {
		mech_gssapi_log_error(auth_request, major_status,
				      GSS_C_GSS_CODE,
				      "processing incoming data");
		mech_gssapi_log_error(auth_request, minor_status,
				      GSS_C_MECH_CODE,
				      "processing incoming data");
		return -1;
	} 

	switch (major_status) {
	case GSS_S_COMPLETE:
		if (!mech_gssapi_oid_cmp(mech_type, &mech_gssapi_krb5_oid)) {
			e_info(auth_request->mech_event,
			       "GSSAPI mechanism not Kerberos5");
			ret = -1;
		} else if (get_display_name(auth_request, request->authn_name,
					    &name_type, &username) < 0)
			ret = -1;
		else if (!auth_request_set_username(auth_request, username,
						    &error)) {
			e_info(auth_request->mech_event,
			       "authn_name: %s", error);
			ret = -1;
		} else {
			request->sasl_gssapi_state = GSS_STATE_WRAP;
			e_debug(auth_request->mech_event,
				"security context state completed.");
		}
		break;
	case GSS_S_CONTINUE_NEEDED:
		e_debug(auth_request->mech_event,
			"Processed incoming packet correctly, "
			"waiting for another.");
		break;
	default:
		e_error(auth_request->mech_event,
			"Received unexpected major status %d", major_status);
		break;
	}

	if (ret == 0) {
		if (output_token.length > 0) {
			auth_request_handler_reply_continue(auth_request,
							    output_token.value,
							    output_token.length);
		} else {
			/* If there is no output token, go straight to wrap,
			   which is expecting an empty input token. */
			ret = mech_gssapi_wrap(request, output_token);
		}
	}
	(void)gss_release_buffer(&minor_status, &output_token);
	return ret;
}

static int
mech_gssapi_wrap(struct gssapi_auth_request *request, gss_buffer_desc inbuf)
{
	OM_uint32 major_status, minor_status;
	gss_buffer_desc outbuf;
	unsigned char ret[4];

	/* The client's return data should be empty here */
	
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

	if (GSS_ERROR(major_status) != 0) {
		mech_gssapi_log_error(&request->auth_request, major_status,
			GSS_C_GSS_CODE, "sending security layer negotiation");
		mech_gssapi_log_error(&request->auth_request, minor_status,
			GSS_C_MECH_CODE, "sending security layer negotiation");
		return -1;
	} 

	e_debug(request->auth_request.mech_event,
		"Negotiated security layer");

	auth_request_handler_reply_continue(&request->auth_request,
					    outbuf.value, outbuf.length);

	(void)gss_release_buffer(&minor_status, &outbuf);
	request->sasl_gssapi_state = GSS_STATE_UNWRAP;
	return 0;
}

#ifdef USE_KRB5_USEROK
static bool
k5_principal_is_authorized(struct auth_request *request, const char *name)
{
	const char *value, *const *authorized_names, *const *tmp;

	value = auth_fields_find(request->extra_fields, "k5principals");
	if (value == NULL)
		return FALSE;

	authorized_names = t_strsplit_spaces(value, ",");
	for (tmp = authorized_names; *tmp != NULL; tmp++) {
		if (strcmp(*tmp, name) == 0) {
			e_debug(request->mech_event,
				"authorized by k5principals field: %s", name);
			return TRUE;
		}
	}
	return FALSE;
}

static bool
mech_gssapi_krb5_userok(struct gssapi_auth_request *request,
			gss_name_t name, const char *login_user,
			bool check_name_type)
{
	krb5_context ctx;
	krb5_principal princ;
	krb5_error_code krb5_err;
	gss_OID name_type;
	const char *princ_display_name;
	bool authorized = FALSE;

	/* Parse out the principal's username */
	if (get_display_name(&request->auth_request, name, &name_type,
			     &princ_display_name) < 0)
		return FALSE;

	if (!mech_gssapi_oid_cmp(name_type, GSS_KRB5_NT_PRINCIPAL_NAME) &&
	    check_name_type) {
		e_info(request->auth_request.mech_event,
		       "OID not kerberos principal name");
		return FALSE;
	}

	/* Init a krb5 context and parse the principal username */
	krb5_err = krb5_init_context(&ctx);
	if (krb5_err != 0) {
		e_error(request->auth_request.mech_event,
			"krb5_init_context() failed: %d", (int)krb5_err);
		return FALSE;
	}
	krb5_err = krb5_parse_name(ctx, princ_display_name, &princ);
	if (krb5_err != 0) {
		/* writing the error string would be better, but we probably
		   rarely get here and there doesn't seem to be a standard
		   way of getting it */
		e_info(request->auth_request.mech_event,
		       "krb5_parse_name() failed: %d",
		       (int)krb5_err);
	} else {
		/* See if the principal is in the list of authorized
		 * principals for the user */
		authorized = k5_principal_is_authorized(&request->auth_request,
							princ_display_name);

		/* See if the principal is authorized to act as the
		   specified (UNIX) user */
		if (!authorized) {
			authorized = krb5_boolean2bool(krb5_kuserok(ctx, princ, login_user));
		}

		krb5_free_principal(ctx, princ);
	}
	krb5_free_context(ctx);
	return authorized;
}
#endif

static int
mech_gssapi_userok(struct gssapi_auth_request *request, const char *login_user)
{
	struct auth_request *auth_request = &request->auth_request;
	OM_uint32 major_status, minor_status;
	int equal_authn_authz;
#ifdef HAVE___GSS_USEROK
	int login_ok;
#endif

	/* if authn and authz names equal, don't bother checking further. */
	major_status = gss_compare_name(&minor_status,
					request->authn_name,
					request->authz_name,
					&equal_authn_authz);
	if (GSS_ERROR(major_status) != 0) {
		mech_gssapi_log_error(auth_request, major_status,
				      GSS_C_GSS_CODE,
				      "gss_compare_name failed");
		return -1;
	}

	if (equal_authn_authz != 0)
		return 0;

	/* handle cross-realm authentication */
#ifdef HAVE___GSS_USEROK
	/* Solaris */
	major_status = __gss_userok(&minor_status, request->authn_name,
				    login_user, &login_ok);
	if (GSS_ERROR(major_status) != 0) {
		mech_gssapi_log_error(auth_request, major_status,
				      GSS_C_GSS_CODE, "__gss_userok failed");
		return -1;
	} 

	if (login_ok == 0) {
		e_info(auth_request->mech_event,
		       "User not authorized to log in as %s", login_user);
		return -1;
	}
	return 0;
#elif defined(USE_KRB5_USEROK)
	if (!mech_gssapi_krb5_userok(request, request->authn_name,
				     login_user, TRUE)) {
		e_info(auth_request->mech_event,
		       "User not authorized to log in as %s", login_user);
		return -1;
	}

	return 0;
#else
	e_info(auth_request->mech_event,
	       "Cross-realm authentication not supported "
	       "(authn_name=%s, authz_name=%s)", request->auth_request.original_username, login_user);
	return -1;
#endif
}

static void
gssapi_credentials_callback(enum passdb_result result,
			    const unsigned char *credentials ATTR_UNUSED,
			    size_t size ATTR_UNUSED,
			    struct auth_request *request)
{
	struct gssapi_auth_request *gssapi_request =
		(struct gssapi_auth_request *)request;

	/* We don't care much whether the lookup succeeded or not because GSSAPI
	 * does not strictly require a passdb. But if a passdb is configured,
	 * now the k5principals field will have been filled in. */
	switch (result) {
	case PASSDB_RESULT_INTERNAL_FAILURE:
		auth_request_internal_failure(request);
		return;
	case PASSDB_RESULT_USER_DISABLED:
	case PASSDB_RESULT_PASS_EXPIRED:
		/* user is explicitly disabled, don't allow it to log in */
		auth_request_fail(request);
		return;
	case PASSDB_RESULT_NEXT:
	case PASSDB_RESULT_SCHEME_NOT_AVAILABLE:
	case PASSDB_RESULT_USER_UNKNOWN:
	case PASSDB_RESULT_PASSWORD_MISMATCH:
	case PASSDB_RESULT_OK:
		break;
	}

	if (mech_gssapi_userok(gssapi_request, request->user) == 0)
		auth_request_success(request, NULL, 0);
	else
		auth_request_fail(request);
}

static int
mech_gssapi_unwrap(struct gssapi_auth_request *request, gss_buffer_desc inbuf)
{
	struct auth_request *auth_request = &request->auth_request;
	OM_uint32 major_status, minor_status;
	gss_buffer_desc outbuf;
	const char *login_user, *error;
	unsigned char *name;
	size_t name_len;

	major_status = gss_unwrap(&minor_status, request->gss_ctx,
				  &inbuf, &outbuf, NULL, NULL);

	if (GSS_ERROR(major_status) != 0) {
		mech_gssapi_log_error(auth_request, major_status,
				      GSS_C_GSS_CODE,
				      "final negotiation: gss_unwrap");
		return -1;
	} 

	/* outbuf[0] contains bitmask for selected security layer,
	   outbuf[1..3] contains maximum output_message size */
	if (outbuf.length < 4) {
		e_error(auth_request->mech_event,
			"Invalid response length");
		return -1;
	}

	if (outbuf.length > 4) {
		name = (unsigned char *)outbuf.value + 4;
		name_len = outbuf.length - 4;

		if (data_has_nuls(name, name_len)) {
			e_info(auth_request->mech_event,
			       "authz_name has NULs");
			return -1;
		}

		login_user = p_strndup(auth_request->pool, name, name_len);
		request->authz_name = import_name(auth_request, name, name_len);
	} else {
		request->authz_name = duplicate_name(auth_request,
						     request->authn_name);
		if (get_display_name(auth_request, request->authz_name,
				     NULL, &login_user) < 0)
			return -1;
	}

	if (request->authz_name == GSS_C_NO_NAME) {
		e_info(auth_request->mech_event,
		       "no authz_name");
		return -1;
	}

	/* Set username early, so that the credential lookup is for the
	 * authorizing user. This means the username in subsequent log
	 * messages will be the authorization name, not the authentication
	 * name, which may mean that future log messages should be adjusted
	 * to log the right thing. */
	if (!auth_request_set_username(auth_request, login_user, &error)) {
		e_info(auth_request->mech_event,
		       "authz_name: %s", error);
		return -1;
	}

	/* Continue in callback once auth_request is populated with passdb
	   information. */
	auth_request->passdb_success = TRUE; /* default to success */
	auth_request_lookup_credentials(&request->auth_request, "",
					gssapi_credentials_callback);
	return 0;
}

static void
mech_gssapi_auth_continue(struct auth_request *request,
			  const unsigned char *data, size_t data_size)
{
	struct gssapi_auth_request *gssapi_request = 
		(struct gssapi_auth_request *)request;
	gss_buffer_desc inbuf;
	int ret = -1;

	inbuf.value = (void *)data;
	inbuf.length = data_size;

	switch (gssapi_request->sasl_gssapi_state) {
	case GSS_STATE_SEC_CONTEXT:
		ret = mech_gssapi_sec_context(gssapi_request, inbuf);
		break;
	case GSS_STATE_WRAP:
		ret = mech_gssapi_wrap(gssapi_request, inbuf);
		break;
	case GSS_STATE_UNWRAP:
		ret = mech_gssapi_unwrap(gssapi_request, inbuf);
		break;
	default:
		i_unreached();
	}
	if (ret < 0)
		auth_request_fail(request);
}

static void
mech_gssapi_auth_initial(struct auth_request *request,
			 const unsigned char *data, size_t data_size)
{
	struct gssapi_auth_request *gssapi_request = 
		(struct gssapi_auth_request *)request;
	OM_uint32 major_status;
	
	major_status =
		obtain_service_credentials(request,
					   &gssapi_request->service_cred);

	if (GSS_ERROR(major_status) != 0) {
		auth_request_internal_failure(request);
		return;
	}
	gssapi_request->authn_name = GSS_C_NO_NAME;
	gssapi_request->authz_name = GSS_C_NO_NAME;

	gssapi_request->sasl_gssapi_state = GSS_STATE_SEC_CONTEXT;

	if (data_size == 0) {
		/* The client should go first */
		auth_request_handler_reply_continue(request, NULL, 0);
	} else {
		mech_gssapi_auth_continue(request, data, data_size);
	}
}

static void
mech_gssapi_auth_free(struct auth_request *request)
{
	struct gssapi_auth_request *gssapi_request =
		(struct gssapi_auth_request *)request;
	OM_uint32 minor_status;

	if (gssapi_request->gss_ctx != GSS_C_NO_CONTEXT) {
		(void)gss_delete_sec_context(&minor_status,
					     &gssapi_request->gss_ctx,
					     GSS_C_NO_BUFFER);
	}

	(void)gss_release_cred(&minor_status, &gssapi_request->service_cred);
	if (gssapi_request->authn_name != GSS_C_NO_NAME) {
		(void)gss_release_name(&minor_status,
				       &gssapi_request->authn_name);
	}
	if (gssapi_request->authz_name != GSS_C_NO_NAME) {
		(void)gss_release_name(&minor_status,
				       &gssapi_request->authz_name);
	}
	pool_unref(&request->pool);
}

const struct mech_module mech_gssapi = {
	"GSSAPI",

	.flags = 0,
	.passdb_need = MECH_PASSDB_NEED_NOTHING,

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

	.flags = 0,
	.passdb_need = MECH_PASSDB_NEED_NOTHING,

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
	if (mech_module_find(mech_gssapi_spnego.mech_name) == NULL)
		mech_register_module(&mech_gssapi_spnego);
#endif
}

void mech_gssapi_deinit(void)
{
#ifdef HAVE_GSSAPI_SPNEGO
	const struct mech_module *mech;

	mech = mech_module_find(mech_gssapi_spnego.mech_name);
	if (mech != NULL && mech->auth_new == mech_gssapi_auth_new)
		mech_unregister_module(&mech_gssapi_spnego);
#endif
	mech_unregister_module(&mech_gssapi);
}
#endif

#endif
