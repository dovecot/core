#ifndef SASL_COMMON_H
#define SASL_COMMON_H

/*
 * Absolute limits
 */

#define SASL_MAX_MESSAGE_SIZE (64 * 1024)

/*
 * Mechanism security flags
 */

enum sasl_mech_security_flags {
	/* Don't advertise this as available SASL mechanism (eg. APOP) */
	SASL_MECH_SEC_PRIVATE		= 0x0001,
	/* Anonymous authentication */
	SASL_MECH_SEC_ANONYMOUS		= 0x0002,
	/* Transfers plaintext passwords */
	SASL_MECH_SEC_PLAINTEXT		= 0x0004,
	/* Subject to passive (dictionary) attack */
	SASL_MECH_SEC_DICTIONARY	= 0x0008,
	/* Subject to active (non-dictionary) attack */
	SASL_MECH_SEC_ACTIVE		= 0x0010,
	/* Provides forward secrecy between sessions */
	SASL_MECH_SEC_FORWARD_SECRECY	= 0x0020,
	/* Provides mutual authentication */
	SASL_MECH_SEC_MUTUAL_AUTH	= 0x0040,
	/* Allow NULs in input data */
	SASL_MECH_SEC_ALLOW_NULS	= 0x0080,
	/* Requires channel binding */
	SASL_MECH_SEC_CHANNEL_BINDING   = 0x0100,
};

/*
 * Mechanism names
 */

#define SASL_MECH_NAME_ANONYMOUS		"ANONYMOUS"
#define SASL_MECH_NAME_CRAM_MD5			"CRAM-MD5"
#define SASL_MECH_NAME_DIGEST_MD5		"DIGEST-MD5"
#define SASL_MECH_NAME_EXTERNAL			"EXTERNAL"
#define SASL_MECH_NAME_GSSAPI			"GSSAPI"
#define SASL_MECH_NAME_GSS_SPNEGO		"GSS-SPNEGO"
#define SASL_MECH_NAME_LOGIN			"LOGIN"
#define SASL_MECH_NAME_OAUTHBEARER		"OAUTHBEARER"
#define SASL_MECH_NAME_OTP			"OTP"
#define SASL_MECH_NAME_PLAIN			"PLAIN"
#define SASL_MECH_NAME_SCRAM_SHA_1		"SCRAM-SHA-1"
#define SASL_MECH_NAME_SCRAM_SHA_1_PLUS		"SCRAM-SHA-1-PLUS"
#define SASL_MECH_NAME_SCRAM_SHA_256		"SCRAM-SHA-256"
#define SASL_MECH_NAME_SCRAM_SHA_256_PLUS	"SCRAM-SHA-256-PLUS"

#define SASL_MECH_NAME_NTLM			"NTLM"
#define SASL_MECH_NAME_XOAUTH2			"XOAUTH2"

#endif
