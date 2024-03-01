#ifndef ISTREAM_DOT_H
#define ISTREAM_DOT_H

enum istream_dot_flags {
	/* If asserted, the trailing [CR]LF before "." line isn't returned. */
	ISTREAM_DOT_NO_TRIM    = 0x00,
	ISTREAM_DOT_TRIM_TRAIL = 0x01,

	/* If not asserted, accept only CR-LF-'.'-CR-LF as the End Of Text
	   sequence. If asserted, also accept sequences missing one or both
	   of the CRs, i.e. LF-'.'-LF, CR-LF-'.'-LF, LF-'.'-CR-LF */
	ISTREAM_DOT_STRICT_EOT = 0x00,
	ISTREAM_DOT_LOOSE_EOT  = 0x02,
};

/* Create input stream for reading SMTP DATA style message: Drop initial "."
   from lines beginning with it. Return EOF on line that contains only "." */
struct istream *
i_stream_create_dot(struct istream *input, enum istream_dot_flags flags);

#endif
