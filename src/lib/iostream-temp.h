#ifndef IOSTREAM_TEMP_H
#define IOSTREAM_TEMP_H

/* Start writing to given output stream. The data is initially written to
   memory, and later to a temporary file that is immediately unlinked. */
struct ostream *iostream_temp_create(const char *temp_path_prefix);
/* Finished writing to stream. Return input stream for it and free the
   output stream. */
struct istream *iostream_temp_finish(struct ostream **output,
				     size_t max_buffer_size);

#endif
