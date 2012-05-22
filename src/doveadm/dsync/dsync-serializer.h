#ifndef DSYNC_SERIALIZER_H
#define DSYNC_SERIALIZER_H

#define NULL_CHR '\002'

struct dsync_serializer *dsync_serializer_init(const char *const keys[]);
void dsync_serializer_deinit(struct dsync_serializer **serializer);

const char *
dsync_serializer_encode_header_line(struct dsync_serializer *serializer);
struct dsync_serializer_encoder *
dsync_serializer_encode_begin(struct dsync_serializer *serializer);
void dsync_serializer_encode_add(struct dsync_serializer_encoder *encoder,
				 const char *key, const char *value);
void dsync_serializer_encode_finish(struct dsync_serializer_encoder **encoder,
				    string_t *output);

#endif
