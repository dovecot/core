#ifndef CLIENT_H
#define CLIENT_H

#include "net.h"
#include "smtp-server.h"

#define CLIENT_MAIL_DATA_MAX_INMEMORY_SIZE (1024*128)

struct mail_storage;
struct mail_deliver_context;
union lmtp_module_context;
struct lmtp_recipient;
struct client;

struct lmtp_local_deliver_context {
	struct mail *src_mail;
	const char *session_id;
	struct timeval delivery_time_started;

	struct mail_user *rcpt_user;
	const char *rcpt_default_mailbox;

	const struct mail_storage_settings *mail_set;
	const struct smtp_submit_settings *smtp_set;
	const struct lda_settings *lda_set;

	struct mail_deliver_session *session;
};

struct client_state {
	const char *name;
	unsigned int session_id_seq;

	struct istream *data_input;
	uoff_t data_size;

	struct timeval data_end_timeval;

	struct ostream *mail_data_output;

	const char *added_headers_local;
	const char *added_headers_proxy;
};

struct lmtp_client_vfuncs {
	void (*destroy)(struct client *client, const char *enh_code,
			const char *reason);

	void (*trans_start)(struct client *client,
			    struct smtp_server_transaction *trans);
	void (*trans_free)(struct client *client,
			   struct smtp_server_transaction *trans);

	int (*cmd_mail)(struct client *client, struct smtp_server_cmd_ctx *cmd,
			struct smtp_server_cmd_mail *data);
	int (*cmd_rcpt)(struct client *client, struct smtp_server_cmd_ctx *cmd,
			struct lmtp_recipient *lrcpt);
	int (*cmd_data)(struct client *client,
			struct smtp_server_cmd_ctx *cmd,
			struct smtp_server_transaction *trans,
			struct istream *data_input, uoff_t data_size);

	int (*local_deliver)(struct client *client,
			     struct lmtp_recipient *lrcpt,
			     struct smtp_server_cmd_ctx *cmd,
			     struct smtp_server_transaction *trans,
			     struct lmtp_local_deliver_context *lldctx);
};

struct client {
	struct client *prev, *next;
	pool_t pool;

	struct lmtp_client_vfuncs v;
	struct event *event;

	const struct setting_parser_info *user_set_info;
	const struct lda_settings *unexpanded_lda_set;
	const struct lmtp_settings *lmtp_set;
	const struct master_service_settings *service_set;

	struct smtp_server_connection *conn;
	enum smtp_server_state last_state;

	struct ip_addr remote_ip, local_ip, real_local_ip, real_remote_ip;
	in_port_t remote_port, local_port, real_local_port, real_remote_port;

	struct mail_user *raw_mail_user;
	const char *my_domain;

	pool_t state_pool;
	struct client_state state;
	struct istream *dot_input;
	struct lmtp_local *local;
	struct lmtp_proxy *proxy;

	/* Module-specific contexts. */
	ARRAY(union lmtp_module_context *) module_contexts;

	bool disconnected:1;
	bool destroyed:1;
};

struct lmtp_module_register {
	unsigned int id;
};

union lmtp_module_context {
	struct lmtp_client_vfuncs super;
	struct lmtp_module_register *reg;
};
extern struct lmtp_module_register lmtp_module_register;

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
