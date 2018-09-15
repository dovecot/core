#ifndef SUBMISSION_BACKEND_H
#define SUBMISSION_BACKEND_H

struct submission_backend;

struct submission_backend_vfuncs {
	void (*destroy)(struct submission_backend *backend);

	void (*start)(struct submission_backend *backend);

	void (*client_input_pre)(struct submission_backend *backend);
	void (*client_input_post)(struct submission_backend *backend);

	uoff_t (*get_max_mail_size)(struct submission_backend *backend);

	int (*cmd_helo)(struct submission_backend *backend,
			struct smtp_server_cmd_ctx *cmd,
			struct smtp_server_cmd_helo *data);

	int (*cmd_mail)(struct submission_backend *backend,
			struct smtp_server_cmd_ctx *cmd,
			struct smtp_server_cmd_mail *data);
	int (*cmd_rcpt)(struct submission_backend *backend,
			struct smtp_server_cmd_ctx *cmd,
			struct smtp_server_cmd_rcpt *data);
	int (*cmd_rset)(struct submission_backend *backend,
			struct smtp_server_cmd_ctx *cmd);
	int (*cmd_data)(struct submission_backend *backend,
			struct smtp_server_cmd_ctx *cmd,
			struct smtp_server_transaction *trans,
			struct istream *data_input);

	int (*cmd_vrfy)(struct submission_backend *backend,
			struct smtp_server_cmd_ctx *cmd,
			const char *param);
	int (*cmd_noop)(struct submission_backend *backend,
			struct smtp_server_cmd_ctx *cmd);

	int (*cmd_quit)(struct submission_backend *backend,
			struct smtp_server_cmd_ctx *cmd);
};

struct submission_backend {
	struct client *client;

	struct submission_backend *prev, *next;

	struct submission_backend_vfuncs v;

	bool started:1;
};

void submission_backend_init(struct submission_backend *backend,
			     struct client *client,
			     const struct submission_backend_vfuncs *vfunc);
void submission_backends_destroy_all(struct client *client);

void submission_backend_start(struct submission_backend *backend);
void submission_backend_started(struct submission_backend *backend,
				enum smtp_capability caps);

void submission_backends_client_input_pre(struct client *client);
void submission_backends_client_input_post(struct client *client);

uoff_t submission_backend_get_max_mail_size(struct submission_backend *backend);

void submission_backend_helo_reply_submit(struct submission_backend *backend,
					  struct smtp_server_cmd_ctx *cmd,
					  struct smtp_server_cmd_helo *data);
int submission_backend_cmd_helo(struct submission_backend *backend,
				struct smtp_server_cmd_ctx *cmd,
				struct smtp_server_cmd_helo *data);

int submission_backend_cmd_mail(struct submission_backend *backend,
				struct smtp_server_cmd_ctx *cmd,
				struct smtp_server_cmd_mail *data);
int submission_backend_cmd_rcpt(struct submission_backend *backend,
				struct smtp_server_cmd_ctx *cmd,
				struct smtp_server_cmd_rcpt *data);
int submission_backend_cmd_rset(struct submission_backend *backend,
				struct smtp_server_cmd_ctx *cmd);
int submission_backend_cmd_data(struct submission_backend *backend,
				struct smtp_server_cmd_ctx *cmd,
				struct smtp_server_transaction *trans,
				struct istream *data_input);

int submission_backend_cmd_vrfy(struct submission_backend *backend,
				struct smtp_server_cmd_ctx *cmd,
				const char *param);
int submission_backend_cmd_noop(struct submission_backend *backend,
				struct smtp_server_cmd_ctx *cmd);

int submission_backend_cmd_quit(struct submission_backend *backend,
				struct smtp_server_cmd_ctx *cmd);

#endif
