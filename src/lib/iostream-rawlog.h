#ifndef IOSTREAM_RAWLOG_H
#define IOSTREAM_RAWLOG_H

enum iostream_rawlog_flags {
	IOSTREAM_RAWLOG_FLAG_AUTOCLOSE	= 0x01,
	IOSTREAM_RAWLOG_FLAG_BUFFERED	= 0x02,
	IOSTREAM_RAWLOG_FLAG_TIMESTAMP	= 0x04
};

/* Create rawlog *.in and *.out files to the given directory. */
int ATTR_NOWARN_UNUSED_RESULT
iostream_rawlog_create(const char *dir, struct istream **input,
		       struct ostream **output);
/* Create rawlog prefix.in and prefix.out files. */
int ATTR_NOWARN_UNUSED_RESULT
iostream_rawlog_create_prefix(const char *prefix, struct istream **input,
			      struct ostream **output);
/* Create rawlog path, writing both input and output to the same file. */
int ATTR_NOWARN_UNUSED_RESULT
iostream_rawlog_create_path(const char *path, struct istream **input,
			    struct ostream **output);
/* Create rawlog that appends to the given rawlog_output.
   Both input and output are written to the same stream. */
void iostream_rawlog_create_from_stream(struct ostream *rawlog_output,
					struct istream **input,
					struct ostream **output);

#endif
