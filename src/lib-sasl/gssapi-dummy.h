#ifndef GSSAPI_DUMMY_H
#define GSSAPI_DUMMY_H

#ifdef HAVE_GSSAPI
#  include "auth-gssapi.h"
#endif

void gss_dummy_kinit(const char *principal);
void gss_dummy_add_principal(const char *principal);

/* Change the flags returned by gss_init_sec_context(), which are otherwise the
   requested ones plus the integrity and confidentiality flags, unless the
   credential has GSS_KRB5_CRED_NO_CI_FLAGS_X set. The added flags are set
   even if they were also removed. */
#ifdef HAVE_GSSAPI
void gss_dummy_set_ret_flags(OM_uint32 add, OM_uint32 remove);
#endif

/* Make gss_acquire_cred() of an initiator credential and/or
   gss_set_neg_mechs() fail. */
#ifdef HAVE_GSSAPI
void gss_dummy_set_initiator_cred_failures(bool acquire, bool set_neg_mechs);
#endif

void gss_dummy_deinit(void);

#endif
