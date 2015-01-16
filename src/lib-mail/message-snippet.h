#ifndef MESSAGE_SNIPPET_H
#define MESSAGE_SNIPPET_H

/* Generate UTF-8 text snippet from the beginning of the given mail input
   stream. The stream is expected to start at the MIME part's headers whose
   snippet is being generated. Returns 0 if ok, -1 if I/O error.

   Currently only Content-Type: text/ is supported, others will result in an
   empty string. */
int message_snippet_generate(struct istream *input,
			     unsigned int max_snippet_chars,
			     string_t *snippet);

#endif
