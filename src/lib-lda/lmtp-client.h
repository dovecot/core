#ifndef LMTP_CLIENT_H
#define LMTP_CLIENT_H

#define ERRSTR_TEMP_REMOTE_FAILURE "451 4.4.0 Remote server not answering"

/* LMTP/SMTP client code. */

enum lmtp_client_protocol {
	LMTP_CLIENT_PROTOCOL_LMTP,
	LMTP_CLIENT_PROTOCOL_SMTP
};

struct lmtp_client_settings {
	const char *my_hostname;
	const char *mail_from;
	const char *dns_client_socket_path;
};

/* reply contains the reply coming from remote server, or NULL
   if it's a connection error. */
typedef void lmtp_callback_t(bool success, const char *reply, void *context);
/* called when session is finished, either because all RCPT TOs failed or
   because all DATA replies have been received. */
typedef void lmtp_finish_callback_t(void *context);

struct lmtp_client *
lmtp_client_init(const struct lmtp_client_settings *set,
		 lmtp_finish_callback_t *finish_callback, void *context);
void lmtp_client_deinit(struct lmtp_client **client);

int lmtp_client_connect_tcp(struct lmtp_client *client,
			    enum lmtp_client_protocol protocol,
			    const char *host, unsigned int port);
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
/* Start sending input stream as DATA. */
void lmtp_client_send(struct lmtp_client *client, struct istream *data_input);
/* Call this function whenever input stream can potentially be read forward.
   This is useful with non-blocking istreams and tee-istreams. */
void lmtp_client_send_more(struct lmtp_client *client);
/* Fail the connection with line as the reply to unfinished RCPT TO/DATA
   replies. */
void lmtp_client_fail(struct lmtp_client *client, const char *line);
/* Return the state (command reply) the client is currently waiting for. */
const char *lmtp_client_state_to_string(struct lmtp_client *client);
/* Call the given callback whenever client manages to send some more DATA
   output to client. */
void lmtp_client_set_data_output_callback(struct lmtp_client *client,
					  void (*callback)(void *),
					  void *context);

#endif
