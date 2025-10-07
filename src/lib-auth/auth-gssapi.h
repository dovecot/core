#ifndef AUTH_GSSAPI_H
#define AUTH_GSSAPI_H

#ifdef HAVE_GSSAPI_GSSAPI_H
#  include <gssapi/gssapi.h>
#elif defined (HAVE_GSSAPI_H)
#  include <gssapi.h>
#endif

#ifdef HAVE_GSSAPI_GSSAPI_KRB5_H
#  include <gssapi/gssapi_krb5.h>
#elif defined (HAVE_GSSAPI_KRB5_H)
#  include <gssapi_krb5.h>
#endif

#ifdef HAVE_GSSAPI_GSSAPI_EXT_H
#  include <gssapi/gssapi_ext.h>
#endif

#endif
