#ifndef OSTREAM_DOT_H
#define OSTREAM_DOT_H

/* Create output stream for writing SMTP DATA style message: Add additional "."
   to lines that start with ".". Write a line that contains only "." upon
   o_stream_flush(). (This is also called at close(), but it shouldn't be
   relied on since it could fail due to output buffer being full.)

   If output ends with CRLF, force_extra_crlf controls whether additional CRLF
   is written before the "." line. This parameter should match
   i_stream_create_dot()'s send_last_lf parameter (reversed). */
struct ostream *o_stream_create_dot(struct ostream *output,
				    bool force_extra_crlf);

#endif
