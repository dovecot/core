#ifndef OTP_PARSE_H
#define OTP_PARSE_H

int otp_read_hex(const char *data, const char **endptr, unsigned char *hash);
int otp_read_words(const char *data, const char **endptr, unsigned char *hash);
int otp_read_new_params(const char *data, const char **endptr,
			struct otp_state *state);

int otp_parse_response(const char *data, unsigned char *hash, bool hex);
int otp_parse_init_response(const char *data, struct otp_state *new_state,
			    unsigned char *hash, bool hex, const char **error);

int otp_parse_dbentry(const char *text, struct otp_state *state);
const char *otp_print_dbentry(const struct otp_state *state);

#endif
