#ifndef MESSAGE_DECODER_H
#define MESSAGE_DECODER_H

struct message_block;

/* Decode message's contents as UTF-8, both the headers and the MIME bodies.
   The bodies are decoded from quoted-printable and base64 formats if needed.
   If dtcase=TRUE, the data is returned through
   uni_utf8_to_decomposed_titlecase(). */
struct message_decoder_context *message_decoder_init(bool dtcase);
void message_decoder_deinit(struct message_decoder_context **ctx);

/* Decode input and return decoded output. Headers are returned only in their
   full multiline forms.

   Returns TRUE if output is given, FALSE if more data is needed. If the input
   ends in a partial character, it's returned in the next output. */
bool message_decoder_decode_next_block(struct message_decoder_context *ctx,
				       struct message_block *input,
				       struct message_block *output);

#endif
