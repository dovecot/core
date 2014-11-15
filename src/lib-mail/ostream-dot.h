#ifndef OSTREAM_DOT_H
#define OSTREAM_DOT_H

/* Create output stream for writing SMTP DATA style message: Add additional "."
   to lines beginning with it. Write line that contains only "." upon close().
 */
struct ostream *o_stream_create_dot(struct ostream *output);

#endif
