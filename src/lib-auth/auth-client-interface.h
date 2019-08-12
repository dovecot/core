#ifndef AUTH_CLIENT_INTERFACE_H
#define AUTH_CLIENT_INTERFACE_H

/* Major version changes are not backwards compatible,
   minor version numbers can be ignored. */
#define AUTH_CLIENT_PROTOCOL_MAJOR_VERSION 1
#define AUTH_CLIENT_PROTOCOL_MINOR_VERSION 2

/* GSSAPI can use quite large packets */
#define AUTH_CLIENT_MAX_LINE_LENGTH 16384

enum mech_security_flags {
	/* Don't advertise this as available SASL mechanism (eg. APOP) */
	MECH_SEC_PRIVATE		= 0x0001,
	/* Anonymous authentication */
	MECH_SEC_ANONYMOUS		= 0x0002,
	/* Transfers plaintext passwords */
	MECH_SEC_PLAINTEXT		= 0x0004,
	/* Subject to passive (dictionary) attack */
	MECH_SEC_DICTIONARY		= 0x0008,
	/* Subject to active (non-dictionary) attack */
	MECH_SEC_ACTIVE			= 0x0010,
	/* Provides forward secrecy between sessions */
	MECH_SEC_FORWARD_SECRECY	= 0x0020,
	/* Provides mutual authentication */
	MECH_SEC_MUTUAL_AUTH		= 0x0040
};

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
