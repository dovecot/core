#ifndef DSYNC_DESERIALIZER_H
#define DSYNC_DESERIALIZER_H

struct dsync_deserializer;
struct dsync_deserializer_decoder;

int dsync_deserializer_init(const char *name, const char *const *required_fields,
			    const char *header_line,
			    struct dsync_deserializer **deserializer_r,
			    const char **error_r);
void dsync_deserializer_deinit(struct dsync_deserializer **deserializer);

int dsync_deserializer_decode_begin(struct dsync_deserializer *deserializer,
				    const char *input,
				    struct dsync_deserializer_decoder **decoder_r,
				    const char **error_r);
bool dsync_deserializer_decode_try(struct dsync_deserializer_decoder *decoder,
				   const char *key, const char **value_r);
/* key must be in required fields. The return value is never NULL. */
const char *
dsync_deserializer_decode_get(struct dsync_deserializer_decoder *decoder,
			      const char *key);
const char *
dsync_deserializer_decoder_get_name(struct dsync_deserializer_decoder *decoder);
void dsync_deserializer_decode_finish(struct dsync_deserializer_decoder **decoder);

#endif
