#ifndef SASL_COMMON_H
#define SASL_COMMON_H

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

#endif
