#ifndef CLIENT_H
#define CLIENT_H

#include "net.h"
#include "smtp-server.h"

#define CLIENT_MAIL_DATA_MAX_INMEMORY_SIZE (1024*128)

struct client;

struct client_state {
	const char *name;
	unsigned int session_id_seq;

	struct timeval data_end_timeval;

	struct ostream *mail_data_output;

	const char *added_headers_local;
	const char *added_headers_proxy;
};

struct lmtp_client_vfuncs {
	void (*destroy)(struct client *client, const char *enh_code,
			const char *reason);
};

struct client {
	struct client *prev, *next;
	pool_t pool;

	struct lmtp_client_vfuncs v;

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

struct client *client_create(int fd_in, int fd_out,
			     const struct master_service_connection *conn);
void client_destroy(struct client *client, const char *enh_code,
		    const char *reason) ATTR_NULL(2, 3);
void client_disconnect(struct client *client, const char *enh_code,
		       const char *reason) ATTR_NULL(2, 3);

const char *client_state_get_name(struct client *client);
void client_state_reset(struct client *client);

void clients_destroy(void);

#endif
