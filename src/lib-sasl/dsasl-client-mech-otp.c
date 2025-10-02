/* Copyright (c) 2025 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "strnum.h"
#include "str-sanitize.h"
#include "hex-binary.h"
#include "randgen.h"
#include "otp.h"
#include "otp-hash.h"

#include "dsasl-client-private.h"

#define OTP_MAX_SEQUENCE (64 * 4096)

/* Sequence count below which we trigger seed reinitialization and
   sequence reset. */
#define MECH_OTP_MIN_SEQ 8

#define IS_LWSP(c) ((c) == ' ' || (c) == '\t')

struct otp_dsasl_client {
	struct dsasl_client client;

	struct otp_state state;
};

static bool
parse_prefix(const unsigned char **_p, const unsigned char *pend,
	     const char *prefix)
{
	const unsigned char *p = *_p;
	size_t prlen = strlen(prefix);

	if (prlen > (size_t)(pend - p))
		return FALSE;
	if (memcmp(p, prefix, prlen) != 0)
		return FALSE;

	*_p = p + prlen;
	return TRUE;
}

static void
skip_lwsp(const unsigned char **_p, const unsigned char *pend)
{
	const unsigned char *p = *_p;

	while (p < pend && IS_LWSP(*p))
		p++;
	*_p = p;
}

static void
parse_field(const unsigned char **_p, const unsigned char *pend,
	    char **field_r)
{
	const unsigned char *p = *_p, *poffset;

	poffset = p;
	while (p < pend && !IS_LWSP(*p))
		p++;

	i_assert(p > poffset);
	*field_r = t_strdup_until_noconst(poffset, p);
	*_p = p;
}

static enum dsasl_client_result
mech_otp_input(struct dsasl_client *client,
	       const unsigned char *input, size_t input_len,
	       const char **error_r)
{
	struct otp_dsasl_client *oclient =
		container_of(client, struct otp_dsasl_client, client);
	const unsigned char *p = input, *pend = input + input_len;
	char *algorithm, *seed;
	uintmax_t sequence;
	int ret;

	/* otp-<algorithm identifier> <sequence integer> <seed>
	 */

	if (p >= pend) {
		*error_r = "Server sent empty challenge";
		return DSASL_CLIENT_RESULT_ERR_PROTOCOL;
	}

	/* otp-<algorithm identifier> */
	if (!parse_prefix(&p, pend, "otp-")) {
		*error_r = "Server sent invalid challenge: "
			"Missing 'otp-' prefix";
		return DSASL_CLIENT_RESULT_ERR_PROTOCOL;
	}
	if (p >= pend || IS_LWSP(*p)) {
		*error_r = "Server sent invalid challenge: "
			"Missing algorithm name";
		return DSASL_CLIENT_RESULT_ERR_PROTOCOL;
	}
	parse_field(&p, pend, &algorithm);
	skip_lwsp(&p, pend);

	/* <sequence integer> */
	if (p >= pend) {
		*error_r = "Server sent incomplete challenge: "
			"Sequence field missing";
		return DSASL_CLIENT_RESULT_ERR_PROTOCOL;
	}
	if (str_parse_data_uintmax(p, pend - p, &sequence, &p) < 0 ||
	    (p < pend && !IS_LWSP(*p)) ||
	    sequence == 0 || sequence > INT_MAX) {
		*error_r = "Server sent invalid challenge: "
			"Invalid sequence field";
		return DSASL_CLIENT_RESULT_ERR_PROTOCOL;
	}
	skip_lwsp(&p, pend);

	/* <seed> */
	if (p >= pend) {
		*error_r = "Server sent incomplete challenge: "
			"Seed field missing";
		return DSASL_CLIENT_RESULT_ERR_PROTOCOL;
	}
	parse_field(&p, pend, &seed);
	seed = str_lcase(seed);
	skip_lwsp(&p, pend);

	/* extended-challenge = otp-challenge 1*LWSP-char capability-list
                        (NL / *LWSP-char)
	   capability-list   = "ext" *("," extension-set-id)
	   extension-set-id  = *<any CHAR except LWSP, CTLs, or ",">
	 */
	if (p >= pend) {
		*error_r = "Server sent incomplete challenge: "
			"Capability list missing";
		return DSASL_CLIENT_RESULT_ERR_PROTOCOL;
	}
	if (!parse_prefix(&p, pend, "ext")) {
		*error_r = "Server sent invalid challenge: "
			"Invalid capability list";
		return DSASL_CLIENT_RESULT_ERR_PROTOCOL;
	}
	if (p < pend && *p == ',') {
		/* skip rest of capability list; we support none */
		while (p < pend && *p > 0x20 && *p < 0x7F)
			p++;
	}
	if (p < pend && *p == '\n')
		p++;
	else
		skip_lwsp(&p, pend);
	if (p < pend) {
		*error_r = "Server sent invalid challenge: "
			"Unrecognized trailing data";
		return DSASL_CLIENT_RESULT_ERR_PROTOCOL;
	}

	/* Check limits */
	if (sequence > OTP_MAX_SEQUENCE) {
		*error_r = t_strdup_printf(
			"Server sent unacceptable challenge: "
			"Sequence out of acceptable range (%"PRIuMAX" > %d)",
			sequence, OTP_MAX_SEQUENCE);
		return DSASL_CLIENT_RESULT_ERR_PROTOCOL;
	}

	/* Find hash algorithm */
	ret = digest_find(algorithm);
	if (ret < 0) {
		*error_r = t_strdup_printf(
			"Server sent unacceptable challenge: "
			"Unsupported hash algorithm: %s",
			str_sanitize(algorithm, 64));
		return DSASL_CLIENT_RESULT_ERR_PROTOCOL;
	}

	/* RFC 2289, Section 6.0:
	   The seed MUST consist of purely alphanumeric characters and MUST be
	   of one to 16 characters in length.
	 */
	size_t si;
	for (si = 0; seed[si] != '\0' && si < 16; si++) {
		if (seed[si] >= '0' && seed[si] <= '9')
			continue;
		else if (seed[si] >= 'a' && seed[si] <= 'z')
			continue;
		break;
	}
	if (seed[si] != '\0') {
		*error_r = "Server sent unacceptable challenge: "
			"Invalid seed string";
		return DSASL_CLIENT_RESULT_ERR_PROTOCOL;
	}

	oclient->state.algo = ret;
	oclient->state.seq = sequence;
	memcpy(oclient->state.seed, seed, si);
	return DSASL_CLIENT_RESULT_OK;
}

static enum dsasl_client_result
mech_otp_output(struct dsasl_client *client,
		const unsigned char **output_r, size_t *output_len_r,
		const char **error_r)
{
	struct otp_dsasl_client *oclient =
		container_of(client, struct otp_dsasl_client, client);
	string_t *str;

	if (client->set.authid == NULL) {
		*error_r = "authid not set";
		return DSASL_CLIENT_RESULT_ERR_INTERNAL;
	}
	if (client->password == NULL) {
		*error_r = "password not set";
		return DSASL_CLIENT_RESULT_ERR_INTERNAL;
	}

	if (oclient->state.seq == 0) {
		str = str_new(client->pool, 128);
		if (client->set.authzid != NULL)
			str_append(str, client->set.authzid);
		str_append_c(str, '\0');
		str_append(str, client->set.authid);

		*output_r = str_data(str);
		*output_len_r = str_len(str);
		return DSASL_CLIENT_RESULT_OK;
	}

	struct otp_state *state = &oclient->state;
	unsigned char hash[OTP_HASH_SIZE];

	otp_hash(state->algo, state->seed, client->password, state->seq, hash);
	if (oclient->state.seq > MECH_OTP_MIN_SEQ) {
		str = str_new(client->pool, 16);
		str_append(str, "hex:");
		binary_to_hex_append(str, hash, sizeof(hash));
	} else {
		unsigned char new_hash[OTP_HASH_SIZE];
		unsigned char random_data[OTP_MAX_SEED_LEN / 2];
		const char *random_hex;

		random_fill(random_data, sizeof(random_data));
		random_hex = binary_to_hex(random_data, sizeof(random_data));
		memcpy(state->seed, random_hex, sizeof(state->seed));
		state->seq = 1024;

		otp_hash(state->algo, state->seed, client->password, state->seq,
			 new_hash);

		str = str_new(client->pool, 128);
		str_append(str, "init-hex:");
		binary_to_hex_append(str, hash, sizeof(hash));
		str_printfa(str, ":%s %d %s:",
			    digest_name(state->algo), state->seq, state->seed);
		binary_to_hex_append(str, new_hash, sizeof(new_hash));
	}

	*output_r = str_data(str);
	*output_len_r = str_len(str);
	return DSASL_CLIENT_RESULT_OK;
}

const struct dsasl_client_mech dsasl_client_mech_otp = {
	.name = SASL_MECH_NAME_OTP,
	.struct_size = sizeof(struct otp_dsasl_client),

	.input = mech_otp_input,
	.output = mech_otp_output,
};
