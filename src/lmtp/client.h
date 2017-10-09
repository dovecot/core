#ifndef CLIENT_H
#define CLIENT_H

#include "net.h"
#include "smtp-server.h"

#define CLIENT_MAIL_DATA_MAX_INMEMORY_SIZE (1024*128)

struct lmtp_recipient {
	struct client *client;

	struct smtp_address *path;
	struct smtp_server_cmd_ctx *rcpt_cmd;
	struct smtp_server_recipient *rcpt;
	unsigned int index;
};

struct client_state {
	const char *name;
	unsigned int session_id_seq;

	struct timeval data_end_timeval;

	/* Initially we start writing to mail_data. If it grows too large,
	   start using mail_data_fd. */
	buffer_t *mail_data;
	int mail_data_fd;
	struct ostream *mail_data_output;

	const char *added_headers_local;
	const char *added_headers_proxy;
};

struct client {
	struct client *prev, *next;
	pool_t pool;

	const struct setting_parser_info *user_set_info;
	const struct lda_settings *unexpanded_lda_set;
	const struct lmtp_settings *lmtp_set;
	const struct master_service_settings *service_set;

	struct smtp_server_connection *conn;
	enum smtp_server_state last_state;

	struct ip_addr remote_ip, local_ip;
	in_port_t remote_port, local_port;

	struct mail_user *raw_mail_user;
	const char *my_domain;

	pool_t state_pool;
	struct client_state state;
	struct istream *dot_input;
	struct lmtp_local *local;
	struct lmtp_proxy *proxy;

	bool disconnected:1;
	bool destroyed:1;
};

struct client *client_create(int fd_in, int fd_out, bool ssl_start,
			     const struct master_service_connection *conn);
void client_destroy(struct client *client, const char *enh_code,
		    const char *reason) ATTR_NULL(2, 3);
void client_disconnect(struct client *client, const char *enh_code,
		       const char *reason) ATTR_NULL(2, 3);

const char *client_state_get_name(struct client *client);
void client_state_reset(struct client *client);

void clients_destroy(void);

#endif
