#ifndef LDAP_SASL_H
#define LDAP_SASL_H

#define HAVE_LDAP_SASL
#ifdef HAVE_SASL_SASL_H
#  include <sasl/sasl.h>
#elif defined (HAVE_SASL_H)
#  include <sasl.h>
#else
#  undef HAVE_LDAP_SASL
#endif
#if !defined(SASL_VERSION_MAJOR) || SASL_VERSION_MAJOR < 2
#  undef HAVE_LDAP_SASL
#endif

#endif
