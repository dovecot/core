#ifndef LMTP_CLIENT_H
#define LMTP_CLIENT_H

#include "net.h"

#define ERRSTR_TEMP_REMOTE_FAILURE "451 4.4.0 Remote server not answering"

/* LMTP/SMTP client code. */

enum lmtp_client_protocol {
	LMTP_CLIENT_PROTOCOL_LMTP,
	LMTP_CLIENT_PROTOCOL_SMTP
};

enum lmtp_client_result {
	/* Command succeeded */
	LMTP_CLIENT_RESULT_OK = 1,
	/* Command failed because remote server returned an error */
	LMTP_CLIENT_RESULT_REMOTE_ERROR = 0,
	/* Command failed because of an internal error (e.g. couldn't connect
	   to remote) */
	LMTP_CLIENT_RESULT_INTERNAL_ERROR = -1
};

struct lmtp_recipient_params {
	const char *dsn_orcpt;
};

struct lmtp_client_times {
	struct timeval connect_started;
	struct timeval banner_received;
	struct timeval data_started;
	struct timeval data_sent;
};

struct lmtp_client_settings {
	const char *my_hostname;
	/* The whole MAIL FROM line, including parameters */
	const char *mail_from;
	const char *dns_client_socket_path;

	/* if remote server supports XCLIENT capability,
	   send the these as ADDR/PORT/TTL/TIMEOUT */
	struct ip_addr source_ip;
	in_port_t source_port;
	/* send TTL as this (default 0 means "don't send it") */
	unsigned int proxy_ttl;
	/* remote is notified that the connection is going to be closed after
	   this many seconds, so it should try to keep lock waits and such
	   lower than this. */
	unsigned int proxy_timeout_secs;
	/* Don't wait an answer from destination server longer than this many
	   seconds (0 = unlimited) */
	unsigned int timeout_secs;
};

/* reply contains the reply coming from remote server, or NULL
   if it's a connection error. */
typedef void lmtp_callback_t(enum lmtp_client_result result,
			     const char *reply, void *context);
/* called when session is finished, either because all RCPT TOs failed or
   because all DATA replies have been received. */
typedef void lmtp_finish_callback_t(void *context);

struct lmtp_client *
lmtp_client_init(const struct lmtp_client_settings *set,
		 lmtp_finish_callback_t *finish_callback, void *context);
void lmtp_client_deinit(struct lmtp_client **client);

int lmtp_client_connect_tcp(struct lmtp_client *client,
			    enum lmtp_client_protocol protocol,
			    const char *host, in_port_t port);
void lmtp_client_close(struct lmtp_client *client);

/* Add headers from given string before the rest of the data. The string must
   use CRLF line feeds and end with CRLF. */
void lmtp_client_set_data_header(struct lmtp_client *client, const char *str);
/* Add recipient to the session. rcpt_to_callback is called once LMTP server
   replies with RCPT TO. If RCPT TO was a succees, data_callback is called
   when DATA replies. */
void lmtp_client_add_rcpt(struct lmtp_client *client, const char *address,
			  lmtp_callback_t *rcpt_to_callback,
			  lmtp_callback_t *data_callback, void *context);
void lmtp_client_add_rcpt_params(struct lmtp_client *client, const char *address,
				 const struct lmtp_recipient_params *params,
				 lmtp_callback_t *rcpt_to_callback,
				 lmtp_callback_t *data_callback, void *context);
/* Start sending input stream as DATA. */
void lmtp_client_send(struct lmtp_client *client, struct istream *data_input);
/* Call this function whenever input stream can potentially be read forward.
   This is useful with non-blocking istreams and tee-istreams. */
void lmtp_client_send_more(struct lmtp_client *client);
/* Fail the connection with line as the reply to unfinished RCPT TO/DATA
   replies. This will be treated as an internal failure. */
void lmtp_client_fail(struct lmtp_client *client, const char *line);
/* Return the state (command reply) the client is currently waiting for. */
const char *lmtp_client_state_to_string(struct lmtp_client *client);
/* Call the given callback whenever client manages to send some more DATA
   output to client. */
void lmtp_client_set_data_output_callback(struct lmtp_client *client,
					  void (*callback)(void *),
					  void *context);
/* Return LMTP client statistics. */
const struct lmtp_client_times *
lmtp_client_get_times(struct lmtp_client *client);

#endif
