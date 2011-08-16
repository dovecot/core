#ifndef ISTREAM_MAIL_STATS_H
#define ISTREAM_MAIL_STATS_H

struct istream *
i_stream_create_mail_stats_counter(struct mailbox_transaction_context *trans,
				   struct istream *input);

#endif
