#ifndef IMAP_STATE_PRIVATE_H
#define IMAP_STATE_PRIVATE_H

#include "seq-range-array.h"
#include "imap-state.h"

struct client;

/* Encode array of seq_range into dest using numpack. */
void imap_state_export_seq_range(buffer_t *dest,
				 const ARRAY_TYPE(seq_range) *range);

/* Decode a numpack-encoded seq_range from [*data, end). Advances *data.
   Returns 0 on success, -1 on truncation or invalid (overflowing) range. */
int imap_state_import_seq_range(const unsigned char **data,
				const unsigned char *end,
				ARRAY_TYPE(seq_range) *range);

/* Read NUL-terminated string from [*data, end) into *str_r. Advances *data
   past the NUL. Returns 0 on success, -1 if no NUL found before end. */
int imap_state_import_string(const unsigned char **data,
			     const unsigned char *end, const char **str_r);

/* Public state-block import handlers, exposed for unit testing. data points
   past the 1-byte type tag. */
enum imap_state_result
imap_state_import_compress(struct client *client, const unsigned char *data,
			   size_t size, size_t *skip_r, const char **error_r);
enum imap_state_result
imap_state_import_enabled_feature(struct client *client,
				  const unsigned char *data, size_t size,
				  size_t *skip_r, const char **error_r);
enum imap_state_result
imap_state_import_searchres(struct client *client, const unsigned char *data,
			    size_t size, size_t *skip_r, const char **error_r);

#endif
