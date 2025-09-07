#ifndef SASL_OAUTH2_H
#define SASL_OAUTH2_H

int sasl_oauth2_kvpair_parse(const unsigned char *data, size_t size,
			     const char **key_r, const char **value_r,
			     const unsigned char **end_r,
			     const char **error_r);

bool sasl_oauth2_kvpair_check_value(const char *value);

#endif
