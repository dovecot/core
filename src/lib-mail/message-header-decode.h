#ifndef __MESSAGE_HEADER_DECODE_H
#define __MESSAGE_HEADER_DECODE_H

/* Return FALSE if you wish to stop decoding. charset is NULL when it's not
   RFC2047-encoded. */
typedef int (*message_header_decode_callback_t)(const unsigned char *data,
						size_t size,
						const char *charset,
						void *context);

/* Decode RFC2047 encoded words. Call specified function for each
   decoded block. */
void message_header_decode(const unsigned char *data, size_t size,
			   message_header_decode_callback_t callback,
			   void *context);

#endif
