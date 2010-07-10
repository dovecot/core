#ifndef DSYNC_PROXY_SERVER_H
#define DSYNC_PROXY_SERVER_H

struct dsync_proxy_server;

struct dsync_proxy_server_command {
	const char *name;
	int (*func)(struct dsync_proxy_server *server,
		    const char *const *args);
};

struct dsync_proxy_server {
	int fd_in, fd_out;
	struct io *io;
	struct istream *input;
	struct ostream *output;
	struct timeout *to;

	struct dsync_worker *worker;

	pool_t cmd_pool;
	struct dsync_proxy_server_command *cur_cmd;
	const char *const *cur_args;

	struct dsync_worker_mailbox_iter *mailbox_iter;
	struct dsync_worker_subs_iter *subs_iter;
	struct dsync_worker_msg_iter *msg_iter;

	struct istream *get_input;
	bool get_input_last_lf;
	uint32_t get_uid, copy_uid;

	unsigned int handshake_received:1;
	unsigned int subs_sending_unsubscriptions:1;
	unsigned int save_finished:1;
	unsigned int finished:1;
};

struct dsync_proxy_server *
dsync_proxy_server_init(int fd_in, int fd_out, struct dsync_worker *worker);
void dsync_proxy_server_deinit(struct dsync_proxy_server **server);

struct dsync_proxy_server_command *
dsync_proxy_server_command_find(const char *name);

#endif
