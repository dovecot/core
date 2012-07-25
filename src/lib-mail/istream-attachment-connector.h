#ifndef ISTREAM_ATTACHMENT_CONNECTOR_H
#define ISTREAM_ATTACHMENT_CONNECTOR_H

/* Start building a message stream. The base_input contains the message
   without attachments. The final stream must be exactly msg_size bytes. */
struct istream_attachment_connector *
istream_attachment_connector_begin(struct istream *base_input, uoff_t msg_size);

/* Add the given input stream as attachment. The attachment starts at the given
   start_offset in the (original) message. If base64_blocks_per_line is
   non-zero, the input is base64-encoded with the given settings. The
   (resulting base64-encoded) input must have exactly encoded_size bytes.

   Returns 0 if the input was ok, -1 if we've already reached msg_size or
   attachment offsets/sizes aren't valid. */
int istream_attachment_connector_add(struct istream_attachment_connector *conn,
				     struct istream *decoded_input,
				     uoff_t start_offset, uoff_t encoded_size,
				     unsigned int base64_blocks_per_line,
				     bool base64_have_crlf,
				     const char **error_r);

struct istream *
istream_attachment_connector_finish(struct istream_attachment_connector **conn);
void istream_attachment_connector_abort(struct istream_attachment_connector **conn);

#endif
