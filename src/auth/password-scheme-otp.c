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

const char *password_generate_otp(const char *pw, const char *data,
				  unsigned int algo)
{
	struct otp_state state;

	if (data != NULL) {
		if (otp_parse_dbentry(data, &state) != 0) {
			i_warning("Invalid OTP data in passdb");
			return "";
		}
	} else {
		/* Generate new OTP credentials from plaintext */
		unsigned char random_data[OTP_MAX_SEED_LEN / 2];

		random_fill(random_data, sizeof(random_data));
		i_strocpy(state.seed, binary_to_hex(random_data,
			OTP_MAX_SEED_LEN / 2), sizeof(state.seed));

		state.seq = 1024;
		state.algo = algo;
	}

	otp_hash(state.algo, state.seed, pw, state.seq, state.hash);

	return otp_print_dbentry(&state);
}
