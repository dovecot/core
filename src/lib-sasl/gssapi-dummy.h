#ifndef GSSAPI_DUMMY_H
#define GSSAPI_DUMMY_H

#ifdef HAVE_GSSAPI
#  include "auth-gssapi.h"
#endif

/* The acceptor's token for an initiator that asked for mutual authentication */
#define GSS_DUMMY_MUTUAL_TOKEN "dummy-mutual"

void gss_dummy_kinit(const char *principal);
void gss_dummy_add_principal(const char *principal);

/* Change the flags returned by gss_init_sec_context(), which are otherwise the
   requested ones plus the integrity and confidentiality flags, unless the
   credential has GSS_KRB5_CRED_NO_CI_FLAGS_X set. The added flags are set
   even if they were also removed. */
#ifdef HAVE_GSSAPI
void gss_dummy_set_ret_flags(OM_uint32 add, OM_uint32 remove);
#endif

/* Make a successful gss_accept_sec_context() return this major status
   instead of GSS_S_COMPLETE, e.g. a supplementary status bit. */
#ifdef HAVE_GSSAPI
void gss_dummy_set_accept_status(OM_uint32 status);
#endif

/* Make gss_accept_sec_context() return no output token, even if the initiator
   asked for mutual authentication. */
#ifdef HAVE_GSSAPI
void gss_dummy_set_accept_no_token(bool no_token);
#endif

/* Make gss_acquire_cred() of an initiator credential and/or
   gss_set_neg_mechs() fail. */
#ifdef HAVE_GSSAPI
void gss_dummy_set_initiator_cred_failures(bool acquire, bool set_neg_mechs);
#endif

/* Make gss_accept_sec_context() fail with GSS_S_BAD_BINDINGS unless the
   initiator gave channel bindings with this application data and no
   addresses. Otherwise the acceptor ignores the channel bindings of the
   initiator. */
void gss_dummy_require_channel_bindings(const void *data, size_t size);
/* Returns the application data of the channel bindings in the last token that
   gss_accept_sec_context() parsed, or NULL if the token had none. */
const buffer_t *gss_dummy_get_token_channel_bindings(void);

void gss_dummy_deinit(void);

#endif
