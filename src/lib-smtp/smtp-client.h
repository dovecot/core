#ifndef SMTP_CLIENT_H
#define SMTP_CLIENT_H

#include "net.h"
#include "smtp-common.h"
#include "smtp-address.h"
#include "smtp-reply.h"

#include "smtp-client-settings.h"

struct smtp_client;
struct smtp_client_request;

struct dns_client;
struct ssl_iostream_settings;

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

struct smtp_client_capability_extra {
	const char *name;

	/* Send these additional custom MAIL parameters if available. */
	const char *const *mail_param_extensions;
	/* Send these additional custom RCPT parameters if available. */
	const char *const *rcpt_param_extensions;
};

struct smtp_client_parameters {
	/* Capabilities that are assumed to be enabled no matter whether the
	   server indicates support. */
	enum smtp_capability forced_capabilities;
	/* Capabilities that are disabled no matter whether the server indicates
	   support. */
	enum smtp_capability disabled_capabilities;
	/* Record these extra capabilities if returned in the EHLO response */
	const char *const *extra_capabilities;

	/* if remote server supports XCLIENT capability,
	   send this data */
	struct smtp_proxy_data proxy_data;

	/* defer sending XCLIENT command until authentication or first mail
	   transaction. */
	bool xclient_defer;
	/* sending even broken MAIL command path (otherwise a broken address
	   is sent as <>) */
	bool mail_send_broken_path;
	/* Yield verbose user-visible errors for commands and connections that
	   failed locally. */
	bool verbose_user_errors;

	/* Settings overrides:
	   When assigned, these values take precedence over the related
	   settings. See smtp-client-settings.h for detailed descriptions.
	 */
	struct {
		/* Timeout for SMTP commands. */
		unsigned int command_timeout_msecs;
		/* Timeout for connecting */
		unsigned int connect_timeout_msecs;
	} overrides;
};

struct smtp_client *smtp_client_init(struct event *event_parent);
void smtp_client_deinit(struct smtp_client **_client);

/* Specify the SSL settings. By default lib-ssl-iostream automatically looks
   them up from settings. */
void smtp_client_set_ssl_settings(struct smtp_client *client,
				  const struct ssl_iostream_settings *ssl);
/* Do all lookups using the specified DNS client. */
void smtp_client_set_dns_client(struct smtp_client *client,
				struct dns_client *dns_client);

void smtp_client_switch_ioloop(struct smtp_client *client);

#endif
