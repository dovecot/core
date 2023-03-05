#ifndef SASL_SERVER_H
#define SASL_SERVER_H

#include "auth-client-interface.h"

#include "sasl-common.h"

enum sasl_passdb_result_status {
	SASL_PASSDB_RESULT_INTERNAL_FAILURE = PASSDB_RESULT_INTERNAL_FAILURE,
	SASL_PASSDB_RESULT_SCHEME_NOT_AVAILABLE = PASSDB_RESULT_SCHEME_NOT_AVAILABLE,

	SASL_PASSDB_RESULT_USER_UNKNOWN = PASSDB_RESULT_USER_UNKNOWN,
	SASL_PASSDB_RESULT_USER_DISABLED = PASSDB_RESULT_USER_DISABLED,
	SASL_PASSDB_RESULT_PASS_EXPIRED = PASSDB_RESULT_PASS_EXPIRED,

	SASL_PASSDB_RESULT_PASSWORD_MISMATCH = PASSDB_RESULT_PASSWORD_MISMATCH,
	SASL_PASSDB_RESULT_OK = PASSDB_RESULT_OK,
};

enum sasl_mech_passdb_need {
	/* Mechanism doesn't need a passdb at all */
	SASL_MECH_PASSDB_NEED_NOTHING = 0,
	/* Mechanism just needs to verify a given plaintext password */
	SASL_MECH_PASSDB_NEED_VERIFY_PLAIN,
	/* Mechanism needs to verify a given challenge+response combination,
	   i.e. there is only a single response from client.
	   (Currently implemented the same as _LOOKUP_CREDENTIALS) */
	SASL_MECH_PASSDB_NEED_VERIFY_RESPONSE,
	/* Mechanism needs to look up credentials with appropriate scheme */
	SASL_MECH_PASSDB_NEED_LOOKUP_CREDENTIALS,
	/* Mechanism needs to look up credentials and also modify them */
	SASL_MECH_PASSDB_NEED_SET_CREDENTIALS,
};

enum sasl_server_output_status {
	/* Internal failure */
	SASL_SERVER_OUTPUT_INTERNAL_FAILURE = -2,
	/* Authentication failed */
	SASL_SERVER_OUTPUT_FAILURE = -1,
	/* Client is challlenged to continue authentication */
	SASL_SERVER_OUTPUT_CONTINUE = 0,
	/* Authentication succeeded */
	SASL_SERVER_OUTPUT_SUCCESS = 1,
};

typedef verify_plain_callback_t sasl_server_verify_plain_callback_t;
typedef lookup_credentials_callback_t sasl_server_lookup_credentials_callback_t;
typedef set_credentials_callback_t sasl_server_set_credentials_callback_t;

struct sasl_server_output {
	enum sasl_server_output_status status;

	const void *data;
	size_t data_size;
};

/*
 * Request
 */

enum sasl_server_authid_type {
	/* Normal authentication ID (username) */
	SASL_SERVER_AUTHID_TYPE_USERNAME = 0,
	/* Anonymous credentials; there is no verified authentication ID. */
	SASL_SERVER_AUTHID_TYPE_ANONYMOUS,
	/* The authentication ID is set and verified by an external source. */
	SASL_SERVER_AUTHID_TYPE_EXTERNAL,
};

#endif
