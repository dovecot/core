#ifndef HTTP_TRANSFER_H
#define HTTP_TRANSFER_H

struct http_transfer_param {
	const char *attribute;
	const char *value;
};
ARRAY_DEFINE_TYPE(http_transfer_param, struct http_transfer_param);

struct http_transfer_coding {
	const char *name;
	ARRAY_TYPE(http_transfer_param) parameters;

};
ARRAY_DEFINE_TYPE(http_transfer_coding, struct http_transfer_coding);


// FIXME: we currently lack a means to get error strings from the input stream

struct istream *
http_transfer_chunked_istream_create(struct istream *input, uoff_t max_size);
struct ostream *
	http_transfer_chunked_ostream_create(struct ostream *output);

#endif

