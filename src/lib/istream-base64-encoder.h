#ifndef ISTREAM_BASE64_H
#define ISTREAM_BASE64_H

struct istream *
i_stream_create_base64_encoder(struct istream *input,
			       unsigned int chars_per_line, bool crlf);

#endif
