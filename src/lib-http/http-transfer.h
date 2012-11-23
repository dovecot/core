#ifndef HTTP_TRANSFER_H
#define HTTP_TRANSFER_H

struct istream *
	http_transfer_chunked_istream_create(struct istream *input);

#endif

