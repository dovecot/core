#ifndef IOSTREAM_RAWLOG_H
#define IOSTREAM_RAWLOG_H

int ATTR_NOWARN_UNUSED_RESULT
iostream_rawlog_create(const char *dir, struct istream **input,
		       struct ostream **output);

#endif
