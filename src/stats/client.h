#ifndef CLIENT_H
#define CLIENT_H

struct client {
	struct client *prev, *next;

	int fd;
	struct io *io;
	struct istream *input;
	struct ostream *output;
	struct timeout *to_pending;

	pool_t cmd_pool;
	struct client_export_cmd *cmd_export;
	int (*cmd_more)(struct client *client);

	/* command iterators. while non-NULL, they've increased the
	   struct's refcount so it won't be deleted during iteration */
	unsigned int iter_count;
	struct mail_command *mail_cmd_iter;
	struct mail_session *mail_session_iter;
	struct mail_user *mail_user_iter;
	struct mail_domain *mail_domain_iter;
	struct mail_ip *mail_ip_iter;
};

struct client *client_create(int fd);
void client_destroy(struct client **client);

bool client_is_busy(struct client *client);
void client_enable_io(struct client *client);

void clients_destroy_all(void);

#endif
