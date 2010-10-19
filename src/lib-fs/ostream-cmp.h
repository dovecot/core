#ifndef OSTREAM_CMP_H
#define OSTREAM_CMP_H

/* Compare given input stream to output being written to output stream. */
struct ostream *
o_stream_create_cmp(struct ostream *output, struct istream *input);
/* Returns TRUE if input and output are equal so far. If the caller needs to
   know if the files are entirely equal, it should check also if input stream
   is at EOF. */
bool o_stream_cmp_equals(struct ostream *output);

bool stream_cmp_block(struct istream *input,
		      const unsigned char *data, size_t size);

#endif
