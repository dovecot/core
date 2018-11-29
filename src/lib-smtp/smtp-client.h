#ifndef SMTP_CLIENT_H
#define SMTP_CLIENT_H

#include "net.h"
#include "smtp-common.h"
#include "smtp-address.h"
#include "smtp-reply.h"

struct smtp_client;
struct smtp_client_request;

#define SMTP_DEFAULT_CONNECT_TIMEOUT_MSECS (1000*30)
#define SMTP_DEFAULT_COMMAND_TIMEOUT_MSECS (1000*60*5)
#define SMTP_DEFAULT_MAX_REPLY_SIZE ((size_t)-1)
#define SMTP_DEFAULT_MAX_DATA_CHUNK_SIZE NET_BLOCK_SIZE
#define SMTP_DEFAULT_MAX_DATA_CHUNK_PIPELINE 4

enum smtp_client_command_error {
	/* Server closed the connection */
	SMTP_CLIENT_COMMAND_ERROR_CONNECTION_CLOSED      =  421,
	/* The command was aborted */
	SMTP_CLIENT_COMMAND_ERROR_ABORTED                = 9000,
	/* DNS lookup failed */
	SMTP_CLIENT_COMMAND_ERROR_HOST_LOOKUP_FAILED,
	/* Failed to establish the connection */
	SMTP_CLIENT_COMMAND_ERROR_CONNECT_FAILED,
	/* Failed to authenticate using the provided credentials */
	SMTP_CLIENT_COMMAND_ERROR_AUTH_FAILED,
	/* Lost the connection after initially succeeded */
	SMTP_CLIENT_COMMAND_ERROR_CONNECTION_LOST,
	/* Got an invalid reply from the server */
	SMTP_CLIENT_COMMAND_ERROR_BAD_REPLY,
	/* We sent a command with a payload stream that broke while reading
	   from it */
	SMTP_CLIENT_COMMAND_ERROR_BROKEN_PAYLOAD,
	/* The server failed to respond before the command timed out */
	SMTP_CLIENT_COMMAND_ERROR_TIMED_OUT
};

struct smtp_client_settings {
	struct ip_addr my_ip;
	const char *my_hostname;
	const char *temp_path_prefix;

	/* Capabilities that are assumed to be enabled no matter whether the
	   server indicates support. */
	enum smtp_capability forced_capabilities;
	/* Record these extra capabilities if returned in the EHLO response */
	const char *const *extra_capabilities;

	struct dns_client *dns_client;
	const char *dns_client_socket_path;

	const struct ssl_iostream_settings *ssl;

	const char *master_user;
	const char *username;
	const char *password;
	const struct dsasl_client_mech *sasl_mech;
	/* Space-separated list of SASL mechanisms to try (in the specified
	   order). The default is to use only SASL PLAIN. */
	const char *sasl_mechanisms;

	const char *rawlog_dir;

	/* Timeout for SMTP commands. Reset every time more data is being
	   sent or received.
	   (default = unlimited) */
	unsigned int command_timeout_msecs;
	/* Timeout for loggging in
		(default = cmd_timeout_msecs) */
	unsigned int connect_timeout_msecs;

	/* Max total size of reply */
	size_t max_reply_size;

	/* Maximum BDAT chunk size for the CHUNKING capability */
	uoff_t max_data_chunk_size;
	/* Maximum pipelined BDAT commands */
	unsigned int max_data_chunk_pipeline;

	/* if remote server supports XCLIENT capability,
	   send this data */
	struct smtp_proxy_data proxy_data;

	/* the kernel send/receive buffer sizes used for the connection sockets.
	   Configuring this is mainly useful for the test suite. The kernel
	   defaults are used when these settings are 0. */
	size_t socket_send_buffer_size;
	size_t socket_recv_buffer_size;

	/* Event to use for the smtp client. For specific transactions this can
	   be overridden with smtp_client_transaction_set_event(). */
	struct event *event;

	/* enable logging debug messages */
	bool debug;
	/* peer is trusted, so e.g. attempt sending XCLIENT data */
	bool peer_trusted;
	/* defer sending XCLIENT command until authentication or first mail
	   transaction. */
	bool xclient_defer;
	/* don't clear password after first successful authentication */
	bool remember_password;
};

struct smtp_client *smtp_client_init(const struct smtp_client_settings *set);
void smtp_client_deinit(struct smtp_client **_client);

void smtp_client_switch_ioloop(struct smtp_client *client);

#endif
