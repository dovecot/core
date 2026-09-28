#ifndef MESSAGE_SNIPPET_H
#define MESSAGE_SNIPPET_H

struct message_part;
struct message_block;
struct message_snippet_context;

/* Generate UTF-8 text snippet from the beginning of the given mail input
   stream. The stream is expected to start at the MIME part's headers whose
   snippet is being generated. Returns 0 if ok, -1 if I/O error.

   Currently only Content-Type: text/ is supported, others will result in an
   empty string. */
int message_snippet_generate(struct istream *input,
			     unsigned int max_snippet_chars,
			     string_t *snippet);

/* Incremental snippet generation from message parser blocks. This can be
   used to generate the snippet while the message is being parsed for other
   reasons, without having to read the message again. A snippet is generated
   for every text/ MIME part (and MIME parts without Content-Type), so the
   caller can afterwards pick the snippet of the wanted MIME part with
   message_snippet_get(). */
struct message_snippet_context *
message_snippet_init(unsigned int max_snippet_chars);
void message_snippet_deinit(struct message_snippet_context **ctx);

/* Feed the next block returned by message_parser_parse_next_block(). Returns
   FALSE if the snippet of the current MIME part is complete, so the rest of
   the part's body doesn't need to be fed anymore. Feeding it anyway is
   allowed, the data is just ignored. */
bool message_snippet_more(struct message_snippet_context *ctx,
			  struct message_block *raw_block);

/* Append the snippet generated for the given MIME part. Returns TRUE if the
   part is a text part whose blocks were fed with message_snippet_more() (the
   snippet may still be empty), FALSE if no snippet was generated for it. */
bool message_snippet_get(struct message_snippet_context *ctx,
			 const struct message_part *part, string_t *snippet);

#endif
