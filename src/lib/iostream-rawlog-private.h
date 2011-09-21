#ifndef IOSTREAM_RAWLOG_PRIVATE_H
#define IOSTREAM_RAWLOG_PRIVATE_H

struct rawlog_iostream {
	struct iostream_private *iostream;

	char *rawlog_path;
	int rawlog_fd;

	bool autoclose_fd;
	bool write_timestamp;
};

void iostream_rawlog_write(struct rawlog_iostream *rstream,
			   const unsigned char *data, size_t size);
void iostream_rawlog_close(struct rawlog_iostream *rstream);

#endif
