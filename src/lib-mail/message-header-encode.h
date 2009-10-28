#ifndef MESSAGE_HEADER_ENCODE_H
#define MESSAGE_HEADER_ENCODE_H

/* Encode UTF-8 input into output wherever necessary. */
void message_header_encode(const char *input, string_t *output);

/* Encode the whole UTF-8 input using "Q" or "B" encoding into output.
   The output is split into multiple lines if necessary. The first line length
   is looked up from the output string. */
void message_header_encode_q(const unsigned char *input, unsigned int len,
			     string_t *output);
void message_header_encode_b(const unsigned char *input, unsigned int len,
			     string_t *output);

#endif
