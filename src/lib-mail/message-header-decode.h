#ifndef MESSAGE_HEADER_DECODE_H
#define MESSAGE_HEADER_DECODE_H

/* Return FALSE if you wish to stop decoding. charset is NULL when it's not
   RFC2047-encoded. */
typedef bool message_header_decode_callback_t(const unsigned char *data,
					      size_t size, const char *charset,
					      void *context);

/* Decode RFC2047 encoded words. Call specified function for each
   decoded block. */
void message_header_decode(const unsigned char *data, size_t size,
			   message_header_decode_callback_t *callback,
			   void *context);

/* Append decoded RFC2047 header as UTF-8 to given buffer. If dtcase=TRUE,
   the header is appended through uni_utf8_to_decomposed_titlecase().
   Returns TRUE if output changed in any way from input. */
bool message_header_decode_utf8(const unsigned char *data, size_t size,
				buffer_t *dest, bool dtcase);

#endif
