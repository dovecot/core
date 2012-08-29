#ifndef IOSTREAM_RAWLOG_PRIVATE_H
#define IOSTREAM_RAWLOG_PRIVATE_H

#define IOSTREAM_RAWLOG_MAX_PREFIX_LEN 3

enum iostream_rawlog_flags {
	IOSTREAM_RAWLOG_FLAG_AUTOCLOSE	= 0x01,
	IOSTREAM_RAWLOG_FLAG_BUFFERED	= 0x02
};

struct rawlog_iostream {
	struct iostream_private *iostream;
	enum iostream_rawlog_flags flags;

	char *rawlog_path;
	int rawlog_fd;
	buffer_t *buffer;

	bool input;
	bool line_continued;
};

void iostream_rawlog_init(struct rawlog_iostream *rstream,
			  enum iostream_rawlog_flags flags, bool input);
void iostream_rawlog_write(struct rawlog_iostream *rstream,
			   const unsigned char *data, size_t size);
void iostream_rawlog_close(struct rawlog_iostream *rstream);

#endif
