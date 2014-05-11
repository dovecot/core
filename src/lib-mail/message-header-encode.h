#ifndef MESSAGE_HEADER_ENCODE_H
#define MESSAGE_HEADER_ENCODE_H

/* Encode UTF-8 input into output wherever necessary using either Q or B
   encoding depending on which takes less space (approximately). */
void message_header_encode(const char *input, string_t *output);
void message_header_encode_data(const unsigned char *input, unsigned int len,
				string_t *output);

/* Encode the whole UTF-8 input using "Q" or "B" encoding into output.
   The output is split into multiple lines if necessary (max 76 chars/line).
   The first line's length is given as parameter. */
void message_header_encode_q(const unsigned char *input, unsigned int len,
			     string_t *output, unsigned int first_line_len);
void message_header_encode_b(const unsigned char *input, unsigned int len,
			     string_t *output, unsigned int first_line_len);

#endif
