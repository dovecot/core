#ifndef DOVEADM_CLIENT_H
#define DOVEADM_CLIENT_H

#include "auth-proxy.h"
#include "iostream-ssl.h"

#define DOVEADM_CLIENT_EXIT_CODE_DISCONNECTED 1000

/* See LOGIN_PROXY_TTL for explanation. */
#define DOVEADM_PROXY_TTL 5

struct doveadm_client;
struct ssl_iostream;

struct doveadm_server_reply {
	int exit_code;
	const char *error;
};

typedef void
doveadm_client_cmd_callback_t(const struct doveadm_server_reply *reply,
			      void *context);

/* Called when a field needs to be printed. If finished=FALSE, the next
   call will continue printing this same field. */
typedef void doveadm_client_print_t(const unsigned char *data,
				    size_t size, bool finished,
				    void *context);

struct doveadm_client_settings {
	/* UNIX socket path to connect to, if non-NULL. */
	const char *socket_path;

	/* Hostname to connect to, if UNIX socket path wasn't specified. */
	const char *hostname;
	/* Host's IP to use, if known. Otherwise DNS lookup is done. */
	struct ip_addr ip;
	/* Port to use for TCP connections. */
	in_port_t port;

	/* Username and password for authentication */
	const char *username, *password;

	/* SSL flags. */
	enum auth_proxy_ssl_flags ssl_flags;
	/* SSL settings. */
	struct ssl_iostream_settings ssl_set;
	/* SSL context, or NULL to create a new one. */
	struct ssl_iostream_context *ssl_ctx;

	/* Enable receiving logs from the server */
	bool log_passthrough;
};

struct doveadm_client_cmd_settings {
	/* TTL for proxying */
	int proxy_ttl;
	/* forward_* fields sent to auth */
	const char *const *forward_fields;
};

/* Duplicate doveadm client settings. Note that the ssl_ctx is referenced by
   this call, so it must be unreferenced later. */
void doveadm_client_settings_dup(const struct doveadm_client_settings *src,
				 struct doveadm_client_settings *dest_r,
				 pool_t pool);

int doveadm_client_create(const struct doveadm_client_settings *set,
			  struct doveadm_client **conn_r,
			  const char **error_r);

void doveadm_client_get_dest(struct doveadm_client *conn,
			     struct ip_addr *ip_r, in_port_t *port_r);
const struct doveadm_client_settings *
doveadm_client_get_settings(struct doveadm_client *conn);

void doveadm_client_set_print(struct doveadm_client *conn,
			      doveadm_client_print_t *callback,
			      void *context);
#define doveadm_client_set_print(conn, callback, context) \
	doveadm_client_set_print(conn, \
		(doveadm_client_print_t *)callback, \
		TRUE ? context : CALLBACK_TYPECHECK(callback, \
			void (*)(const unsigned char *, size_t, bool, typeof(context))))

void doveadm_client_cmd(struct doveadm_client *conn,
			const struct doveadm_client_cmd_settings *set,
			const char *line, struct istream *cmd_input,
			doveadm_client_cmd_callback_t *callback, void *context);

/* Extract iostreams from connection. Afterwards the doveadm_client simply
   waits for itself to be destroyed. */
void doveadm_client_extract(struct doveadm_client *conn,
			    struct istream **istream_r,
			    struct istream **log_istream_r,
			    struct ostream **ostream_r,
			    struct ssl_iostream **ssl_iostream_r);

unsigned int doveadm_clients_count(void);
void doveadm_clients_destroy_all(void);

#endif
