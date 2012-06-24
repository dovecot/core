/*
 * OTP password scheme.
 *
 * Copyright (c) 2006 Andrey Panin <pazke@donpac.ru>
 *
 * This software is released under the MIT license.
 */

#include "lib.h"
#include "hex-binary.h"
#include "password-scheme.h"
#include "randgen.h"
#include "otp.h"

int password_generate_otp(const char *pw, const char *state_data,
			  unsigned int algo, const char **result_r)
{
	struct otp_state state;

	if (state_data != NULL) {
		if (otp_parse_dbentry(state_data, &state) != 0)
			return -1;
	} else {
		/* Generate new OTP credentials from plaintext */
		unsigned char random_data[OTP_MAX_SEED_LEN / 2];
		const char *random_hex;

		random_fill(random_data, sizeof(random_data));
		random_hex = binary_to_hex(random_data, sizeof(random_data));
		if (i_strocpy(state.seed, random_hex, sizeof(state.seed)) < 0)
			i_unreached();

		state.seq = 1024;
		state.algo = algo;
	}

	otp_hash(state.algo, state.seed, pw, state.seq, state.hash);
	*result_r = otp_print_dbentry(&state);
	return 0;
}
