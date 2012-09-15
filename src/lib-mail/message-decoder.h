#ifndef MESSAGE_DECODER_H
#define MESSAGE_DECODER_H

#include "unichar.h"

struct message_header_line;

enum message_cte {
	MESSAGE_CTE_UNKNOWN = 0,
	MESSAGE_CTE_78BIT,
	MESSAGE_CTE_BINARY,
	MESSAGE_CTE_QP,
	MESSAGE_CTE_BASE64
};

enum message_decoder_flags {
	/* Return binary MIME parts as-is without any conversion. */
	MESSAGE_DECODER_FLAG_RETURN_BINARY	= 0x02
};

struct message_block;

/* Decode message's contents as UTF-8, both the headers and the MIME bodies.
   The bodies are decoded from quoted-printable and base64 formats if needed. */
struct message_decoder_context *
message_decoder_init(normalizer_func_t *normalizer,
		     enum message_decoder_flags flags);
void message_decoder_deinit(struct message_decoder_context **ctx);

/* Change the MESSAGE_DECODER_FLAG_RETURN_BINARY flag */
void message_decoder_set_return_binary(struct message_decoder_context *ctx,
				       bool set);

/* Decode input and return decoded output. Headers are returned only in their
   full multiline forms.

   Returns TRUE if output is given, FALSE if more data is needed. If the input
   ends in a partial character, it's returned in the next output. */
bool message_decoder_decode_next_block(struct message_decoder_context *ctx,
				       struct message_block *input,
				       struct message_block *output);

/* Call whenever message changes */
void message_decoder_decode_reset(struct message_decoder_context *ctx);

/* Decode Content-Transfer-Encoding header. */
enum message_cte message_decoder_parse_cte(struct message_header_line *hdr);

#endif
