#include "lib.h"

#ifndef HAVE___GSS_USEROK
#  define USE_KRB5_USEROK
#  include <krb5.h>

#ifdef HAVE_GSSAPI_GSSAPI_KRB5_H
#  include <gssapi/gssapi_krb5.h>
#elif defined (HAVE_GSSAPI_KRB5_H)
#  include <gssapi_krb5.h>
#else
#  undef USE_KRB5_USEROK
#endif

#ifdef USE_KRB5_USEROK
krb5_error_code KRB5_CALLCONV
krb5_parse_name(krb5_context context ATTR_UNUSED, const char *name ATTR_UNUSED,
                krb5_principal *principal_out ATTR_UNUSED)
{
	return 0;
}

void KRB5_CALLCONV
krb5_free_principal(krb5_context context ATTR_UNUSED,
		    krb5_principal val ATTR_UNUSED)
{
}

krb5_error_code KRB5_CALLCONV
krb5_init_context(krb5_context *context ATTR_UNUSED)
{
	return 0;
}

void KRB5_CALLCONV krb5_free_context(krb5_context context ATTR_UNUSED)
{
}

krb5_boolean KRB5_CALLCONV
krb5_kuserok(krb5_context context ATTR_UNUSED,
	     krb5_principal principal ATTR_UNUSED,
	     const char *luser ATTR_UNUSED)
{
	return 0;
}
#endif

#ifdef HAVE_GSSKRB5_REGISTER_ACCEPTOR_IDENTITY
OM_uint32 gsskrb5_register_acceptor_identity(const char *identity ATTR_UNUSED)
{
	return 0;
}
#elif defined (HAVE_KRB5_GSS_REGISTER_ACCEPTOR_IDENTITY)
OM_uint32 KRB5_CALLCONV
krb5_gss_register_acceptor_identity(const char *path ATTR_UNUSED)
{
	return 0;
}
#endif

#endif
