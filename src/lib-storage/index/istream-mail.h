#ifndef ISTREAM_MAIL_H
#define ISTREAM_MAIL_H

struct istream *i_stream_create_mail(struct mail *mail, struct istream *input,
				     bool input_has_body);

#endif
