/*
 * OTP extended response parser.
 *
 * Copyright (c) 2006 Andrey Panin <pazke@donpac.ru>
 *
 * This software is released under the MIT license.
 */

#include "lib.h"
#include "buffer.h"
#include "str.h"
#include "strfuncs.h"
#include "hex-binary.h"

#include "otp.h"

#include <stdlib.h>
#include <ctype.h>

#define IS_LWS(c) ((c) == ' ' || (c) == '\t')

static inline const char *otp_skip_lws(const char *data)
{
	while (*data && IS_LWS(*data))
		data++;
	return data;
}

static inline int otp_check_tail(const char *data)
{
	data = otp_skip_lws(data);

	return *data != 0;
}

int otp_read_hex(const char *data, const char **endptr, unsigned char *hash)
{
	string_t *str;
	buffer_t buf;
	unsigned int i = 0;

	if (data == NULL)
		return -1;

	str = t_str_new(18);
	buffer_create_data(&buf, hash, OTP_HASH_SIZE);

	while (*data) {
		char c = *data;

		if (i_isxdigit(c)) {
			str_append_c(str, c);
			if (++i == OTP_HASH_SIZE * 2) {
				data++;
				break;
			}
		} else if (!IS_LWS(c)) {
			if (endptr)
				*endptr = data;
			return -1;
		}
		data++;
	}

	if (endptr)
		*endptr = data;

	if (i < OTP_HASH_SIZE * 2)
		return -1;

	return hex_to_binary(str_c(str), &buf);
}

#define add_word() do { \
	tmp = otp_lookup_word(str_c(word)); \
	buffer_append(&buf, &tmp, sizeof(tmp)); \
	count++; \
} while (0)

int otp_read_words(const char *data, const char **endptr, unsigned char *hash)
{
	bool space = FALSE;
	unsigned int len = 0, count = 0;
	unsigned int parity = 0, bits[OTP_WORDS_NUMBER], tmp;
	string_t *word;
	buffer_t buf;

	if (data == NULL)
		return -1;

	word = t_str_new(8);

	data = otp_skip_lws(data);

	buffer_create_data(&buf, bits, sizeof(bits));

	for (; *data && (count < OTP_WORDS_NUMBER); data++) {
		char c = *data;

		if (space) {
			if (IS_LWS(c))
				continue;
			else if (i_isalpha(c)) {
				str_append_c(word, c);
				space = FALSE;
				len = 1;
				continue;
			}
		} else {
			if (i_isalpha(c)) {
				if (len > OTP_MAX_WORD_LEN) {
					count = 0;
					break;
				}
				str_append_c(word, c);
				continue;
			} else if (IS_LWS(c)) {
				add_word();
				str_truncate(word, 0);
				space = TRUE;
				continue;
			}		
		}
		break;
	}

	if ((str_len(word) > 0) && (count == OTP_WORDS_NUMBER - 1))
		add_word();

	if (endptr)
		*endptr = data;

	if (count < OTP_WORDS_NUMBER)
		return -1;

	hash[0] = bits[0] >> 3;
	hash[1] = ((bits[0] & 7) << 5) | (bits[1] >> 6);
	hash[2] = ((bits[1] & 0x3f) << 2) | (bits[2] >> 9);
	hash[3] = (bits[2] >> 1) & 0xff;
	hash[4] = ((bits[2] & 3) << 7) | (bits[3] >> 4);
	hash[5] = ((bits[3] & 15) << 4) | (bits[4] >> 7);
	hash[6] = ((bits[4] & 0x7f) << 1) | (bits[5] >> 10);
	hash[7] = (bits[5] >> 2) & 0xff;
	parity = bits[5] & 3;

	return otp_parity(hash) != parity;
}

int otp_read_new_params(const char *data, const char **endptr,
			struct otp_state *state)
{
	const char *p, *s;
	char *end;
	unsigned int i = 0;
	int algo;

	s = p = data;

	while ((*p != 0) && !IS_LWS(*p)) p++;
	if (*p == 0)
		return -1;

	algo = digest_find(t_strdup_until(s, p++));
	if (algo < 0)
		return -2;
	state->algo = algo;

	s = p;
	state->seq = strtol(s, &end, 10); p = end;
	if ((p == s) || !IS_LWS(*p))
		return -3;
	p++;

	while (i_isalnum(*p) && (i < OTP_MAX_SEED_LEN))
		state->seed[i++] = i_tolower(*p++);
	state->seed[i] = 0;

	*endptr = p;
	return 0;
}

int otp_parse_response(const char *data, unsigned char *hash, bool hex)
{
	const char *end;
	int ret = hex ? otp_read_hex(data, &end, hash) :
			otp_read_words(data, &end, hash);
	if (ret < 0)
		return ret;

	return otp_check_tail(end);
}

int otp_parse_init_response(const char *data, struct otp_state *new_state,
			    unsigned char *hash, bool hex, const char **error)
{
	const char *end;
	int ret = hex ? otp_read_hex(data, &end, hash) :
			otp_read_words(data, &end, hash);
	if (ret < 0) {
		*error = "invalid current OTP";
		return ret;
	}

	end = otp_skip_lws(end);
	if (*end++ != ':') {
		*error = "missing colon";
		return -1;
	}

	ret = otp_read_new_params(end, &end, new_state);
	if (ret < 0) {
		*error = "invalid OTP parameters";
		return -1;
	}

	end = otp_skip_lws(end);
	if (*end++ != ':') {
		*error = "missing colon";
		return -1;
	}

	ret = hex ? otp_read_hex(end, &end, new_state->hash) :
		    otp_read_words(end, &end, new_state->hash);
	if (ret < 0) {
		*error = "invalid new OTP";
		return -1;
	}

	if (otp_check_tail(end) != 0) {
		*error = "trailing garbage found";
		return -1;
	}

	return 0;
}

int otp_parse_dbentry(const char *text, struct otp_state *state)
{
	const char *end;
	int ret;

	ret = otp_read_new_params(text, &end, state);
	if (ret != 0)
		return ret;

	if (*end++ != ' ')
		return -1;

	return otp_read_hex(end, NULL, state->hash);
}

const char *otp_print_dbentry(const struct otp_state *state)
{
	return t_strdup_printf("%s %d %s %s", digest_name(state->algo),
				state->seq, state->seed,
				binary_to_hex(state->hash, 8));
}
