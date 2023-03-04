#ifndef AUTH_CLIENT_INTERFACE_H
#define AUTH_CLIENT_INTERFACE_H

#include "sasl-common.h"

/* Major version changes are not backwards compatible,
   minor version numbers can be ignored. */
#define AUTH_CLIENT_PROTOCOL_MAJOR_VERSION 1
#define AUTH_CLIENT_PROTOCOL_MINOR_VERSION 3

/* GSSAPI can use quite large packets */
#define AUTH_CLIENT_MAX_LINE_LENGTH 16384

/* auth failure codes */
#define AUTH_CLIENT_FAIL_CODE_AUTHZFAILED       "authz_fail"
#define AUTH_CLIENT_FAIL_CODE_TEMPFAIL          "temp_fail"
#define AUTH_CLIENT_FAIL_CODE_USER_DISABLED     "user_disabled"
#define AUTH_CLIENT_FAIL_CODE_PASS_EXPIRED      "pass_expired"
#define AUTH_CLIENT_FAIL_CODE_INVALID_BASE64    "invalid_base64"

/* not actually returned from auth service */
#define AUTH_CLIENT_FAIL_CODE_MECH_INVALID      "auth_mech_invalid"
#define AUTH_CLIENT_FAIL_CODE_MECH_SSL_REQUIRED "auth_mech_ssl_required"
#define AUTH_CLIENT_FAIL_CODE_ANONYMOUS_DENIED  "anonymous_denied"

#endif
