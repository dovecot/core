#ifndef IMAP_URLAUTH_H
#define IMAP_URLAUTH_H

#include "net.h"

#define IMAP_URLAUTH_SOCKET_NAME "imap-urlauth"

struct imap_url;
struct imap_msgpart_url;
struct imap_urlauth_context;

struct imap_urlauth_config {
	const char *url_host;
	in_port_t url_port;

	const char *socket_path;
	const char *session_id;

	/* the user who is requesting access to URLAUTHs */
	const char *access_user;
	/* ... is using this service (i.e. imap or submission) */
	const char *access_service;
	/* ... represents these applications */
	const char *const *access_applications;
	/* ... is anonymous? */
	bool access_anonymous;
};

struct imap_urlauth_context *
imap_urlauth_init(struct mail_user *user,
		  const struct imap_urlauth_config *config);
void imap_urlauth_deinit(struct imap_urlauth_context **_uctx);

int imap_urlauth_generate(struct imap_urlauth_context *uctx,
			  const char *mechanism, const char *rumpurl,
			  const char **urlauth_r, const char **client_error_r);

bool imap_urlauth_check(struct imap_urlauth_context *uctx,
			struct imap_url *url, bool ignore_unknown_access,
			const char **error_r);

int imap_urlauth_fetch_parsed(struct imap_urlauth_context *uctx,
			      struct imap_url *url,
			      struct imap_msgpart_url **mpurl_r,
			      enum mail_error *error_code_r,
			      const char **error_r);
int imap_urlauth_fetch(struct imap_urlauth_context *uctx,
		       const char *urlauth, struct imap_msgpart_url **mpurl_r,
		       enum mail_error *error_code_r, const char **error_r);

int imap_urlauth_reset_mailbox_key(struct imap_urlauth_context *uctx,
				   struct mailbox *box);
int imap_urlauth_reset_all_keys(struct imap_urlauth_context *uctx);

#endif
