#ifndef IOSTREAM_RAWLOG_H
#define IOSTREAM_RAWLOG_H

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

#endif
