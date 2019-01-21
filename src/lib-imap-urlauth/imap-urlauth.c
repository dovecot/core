/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "hostpid.h"
#include "var-expand.h"
#include "hmac.h"
#include "sha1.h"
#include "randgen.h"
#include "safe-memset.h"
#include "mail-storage.h"
#include "mail-storage-service.h"
#include "mail-namespace.h"
#include "mail-user.h"
#include "imap-url.h"
#include "imap-msgpart-url.h"
#include "imap-urlauth-backend.h"
#include "imap-urlauth-fetch.h"
#include "imap-urlauth-connection.h"

#include "imap-urlauth-private.h"

#include <time.h>

#define IMAP_URLAUTH_MECH_INTERNAL_VERSION    0x01

#define IMAP_URLAUTH_NORMAL_TIMEOUT_MSECS     5*1000
#define IMAP_URLAUTH_SPECIAL_TIMEOUT_MSECS    3*60*1000

#define URL_HOST_ALLOW_ANY "*"

struct imap_urlauth_context *
imap_urlauth_init(struct mail_user *user,
		  const struct imap_urlauth_config *config)
{
	struct imap_urlauth_context *uctx;
	unsigned int timeout;

	i_assert(*config->url_host != '\0');

	uctx = i_new(struct imap_urlauth_context, 1);
	uctx->user = user;
	uctx->url_host = i_strdup(config->url_host);
	uctx->url_port = config->url_port;

	if (config->access_anonymous)
		uctx->access_user = i_strdup("anonymous");
	else
		uctx->access_user = i_strdup(config->access_user);
	uctx->access_service = i_strdup(config->access_service);
	uctx->access_anonymous = config->access_anonymous;
	if (config->access_applications != NULL &&
	    *config->access_applications != NULL) {
		uctx->access_applications =
			p_strarray_dup(default_pool,
				       config->access_applications);
		timeout = IMAP_URLAUTH_SPECIAL_TIMEOUT_MSECS;
	} else {
		timeout = IMAP_URLAUTH_NORMAL_TIMEOUT_MSECS;
	}

	if (config->socket_path != NULL) {
		uctx->conn = imap_urlauth_connection_init(config->socket_path,
					config->access_service, user, config->session_id, timeout);
	}
	return uctx;
}

void imap_urlauth_deinit(struct imap_urlauth_context **_uctx)
{
	struct imap_urlauth_context *uctx = *_uctx;

	*_uctx = NULL;

	if (uctx->conn != NULL)
		imap_urlauth_connection_deinit(&uctx->conn);
	i_free(uctx->url_host);
	i_free(uctx->access_user);
	i_free(uctx->access_service);
	i_free(uctx->access_applications);
	i_free(uctx);
}

static const unsigned char *
imap_urlauth_internal_generate(const char *rumpurl,
			       const unsigned char mailbox_key[IMAP_URLAUTH_KEY_LEN],
			       size_t *token_len_r)
{
	struct hmac_context hmac;
	unsigned char *token;

	token = t_new(unsigned char, SHA1_RESULTLEN + 1);
	token[0] = IMAP_URLAUTH_MECH_INTERNAL_VERSION;

	hmac_init(&hmac, mailbox_key, IMAP_URLAUTH_KEY_LEN, &hash_method_sha1);
	hmac_update(&hmac, rumpurl, strlen(rumpurl));
	hmac_final(&hmac, token+1);

	*token_len_r = SHA1_RESULTLEN + 1;
	return token;
}

static bool
imap_urlauth_internal_verify(const char *rumpurl,
			     const unsigned char mailbox_key[IMAP_URLAUTH_KEY_LEN],
			     const unsigned char *token, size_t token_len)
{
	const unsigned char *valtoken;
	size_t valtoken_len;

	if (rumpurl == NULL || token == NULL)
		return FALSE;

	valtoken = imap_urlauth_internal_generate(rumpurl, mailbox_key,
						  &valtoken_len);
	if (token_len != valtoken_len)
		return FALSE;

	return memcmp(token, valtoken, valtoken_len) == 0;
}

static bool
access_applications_have_access(struct imap_urlauth_context *uctx,
				struct imap_url *url, const char *const *access_applications)
{
	const char *const *application;

	if (access_applications == NULL)
		return FALSE;

	application = access_applications;
	for (; *application != NULL; application++) {
		const char *app = *application;
		bool have_userid = FALSE;
		size_t len = strlen(app);

		if (app[len-1] == '+')
			have_userid = TRUE;

		if (strncasecmp(url->uauth_access_application, app, len-1) == 0) {
			if (!have_userid) {
				/* this access application must have no userid */
				return url->uauth_access_user == NULL;
			}

			/* this access application must have a userid */
			return (!uctx->access_anonymous && url->uauth_access_user != NULL);
		}
	}
	return FALSE;
}

static bool
imap_urlauth_check_access(struct imap_urlauth_context *uctx,
			  struct imap_url *url, bool ignore_unknown,
			  const char **error_r)
{
	const char *userid;

	if (url->uauth_access_application == NULL) {
		*error_r = "URL is missing URLAUTH";
		return FALSE;
	}

	if (strcmp(uctx->access_service, "imap") == 0) {
		/* these access types are only allowed if URL is accessed through imap */
		if (strcasecmp(url->uauth_access_application, "user") == 0) {
			/* user+<access_user> */
			if (url->uauth_access_user == NULL) {
				*error_r = "URLAUTH `user' access is missing userid";
				return FALSE;
			}
			if (!uctx->access_anonymous ||
				  strcasecmp(url->uauth_access_user, uctx->access_user) == 0)
				return TRUE;
		} else if (strcasecmp(url->uauth_access_application, "authuser") == 0) {
			/* authuser */
			if (!uctx->access_anonymous)
				return TRUE;
		} else if (strcasecmp(url->uauth_access_application, "anonymous") == 0) {
			/* anonymous */
			return TRUE;
		} else if (ignore_unknown || access_applications_have_access
			(uctx, url, uctx->access_applications)) {
			return TRUE;
		}
	} else if (strcmp(uctx->access_service, "submission") == 0) {
		/* accessed directly through submission service */

		if (strcasecmp(url->uauth_access_application, "submit") != 0) {
			userid = url->uauth_access_user == NULL ? "" :
				t_strdup_printf("+%s", url->uauth_access_user);
			*error_r = t_strdup_printf(
				"No '%s%s' access allowed for submission service",
				url->uauth_access_application, userid);
			return FALSE;
		} else if (url->uauth_access_user == NULL) {
			*error_r = "URLAUTH `submit' access is missing userid";
			return FALSE;
		} else if (!uctx->access_anonymous &&
			strcasecmp(url->uauth_access_user, uctx->access_user) == 0) {
			return TRUE;
		}
	}

	userid = url->uauth_access_user == NULL ? "" :
		t_strdup_printf("+%s", url->uauth_access_user);

	if (uctx->access_anonymous) {
		*error_r = t_strdup_printf(
			"No '%s%s' access allowed for anonymous user",
			url->uauth_access_application, userid);
	} else {
		*error_r = t_strdup_printf(
			"No '%s%s' access allowed for user %s",
			url->uauth_access_application, userid, uctx->access_user);
	}
	return FALSE;
}

static bool
imap_urlauth_check_hostport(struct imap_urlauth_context *uctx,
			    struct imap_url *url, const char **client_error_r)
{
	/* validate host */
	/* FIXME: allow host ip/ip6 as well? */
	if (strcmp(uctx->url_host, URL_HOST_ALLOW_ANY) != 0 &&
	    strcmp(url->host.name, uctx->url_host) != 0) {
		*client_error_r = "Invalid URL: Inappropriate host name";
		return FALSE;
	}

	/* validate port */
	if ((url->port == 0 && uctx->url_port != 143) ||
	    (url->port != 0 && uctx->url_port != url->port)) {
		*client_error_r = "Invalid URL: Inappropriate server port";
		return FALSE;
	}
	return TRUE;
}

int imap_urlauth_generate(struct imap_urlauth_context *uctx,
			  const char *mechanism, const char *rumpurl,
			  const char **urlauth_r, const char **client_error_r)
{
	struct mail_user *user = uctx->user;
	enum imap_url_parse_flags url_flags =
		IMAP_URL_PARSE_ALLOW_URLAUTH;
	struct imap_url *url;
	struct imap_msgpart_url *mpurl = NULL;
	struct mailbox *box;
	const char *error;
	enum mail_error error_code;
	unsigned char mailbox_key[IMAP_URLAUTH_KEY_LEN];
	const unsigned char *token;
	size_t token_len;
	int ret;

	/* validate mechanism */
	if (strcasecmp(mechanism, "INTERNAL") != 0) {
		*client_error_r = t_strdup_printf("Unsupported URLAUTH mechanism: %s", mechanism);
		return 0;
	}

	/* validate URL */
	if (imap_url_parse(rumpurl, NULL, url_flags, &url, &error) < 0) {
		*client_error_r = t_strdup_printf("Invalid URL: %s", error);
		return 0;
	}

	if (url->mailbox == NULL || url->uid == 0 || url->search_program != NULL ||
		url->uauth_rumpurl == NULL || url->uauth_mechanism != NULL) {
		*client_error_r = "Invalid URL: Must be an URLAUTH rump URL";
		return 0;
	}

	/* validate expiry time */
	if (url->uauth_expire != (time_t)-1) {
		time_t now = time(NULL);

		if (now > url->uauth_expire) {
			*client_error_r = t_strdup_printf("URLAUTH has already expired");
			return 0;
		}
	}

	/* validate user */
	if (url->userid == NULL) {
		*client_error_r = "Invalid URL: Missing user name";
		return 0;
	}
	if (user->anonymous || strcmp(url->userid, user->username) != 0) {
		*client_error_r = t_strdup_printf(
			"Not permitted to generate URLAUTH for user %s",
			url->userid);
		return 0;
	}

	/* validate host:port */
	if (!imap_urlauth_check_hostport(uctx, url, client_error_r))
		return 0;

	/* validate mailbox */
	if ((ret = imap_msgpart_url_create(user, url, &mpurl, &error)) < 0 ||
	    imap_msgpart_url_verify(mpurl, &error) <= 0) {
		*client_error_r = t_strdup_printf("Invalid URL: %s", error);
		if (mpurl != NULL)
			imap_msgpart_url_free(&mpurl);
		return ret;
	}
	box = imap_msgpart_url_get_mailbox(mpurl);

	/* obtain mailbox key */
	ret = imap_urlauth_backend_get_mailbox_key(box, TRUE, mailbox_key,
						   client_error_r, &error_code);
	if (ret < 0) {
		imap_msgpart_url_free(&mpurl);
		return ret;
	}

	token = imap_urlauth_internal_generate(rumpurl, mailbox_key, &token_len);
	imap_msgpart_url_free(&mpurl);

	*urlauth_r = imap_url_add_urlauth(rumpurl, mechanism, token, token_len);
	return 1;
}

bool imap_urlauth_check(struct imap_urlauth_context *uctx,
			struct imap_url *url, bool ignore_unknown_access,
			const char **error_r)
{
	/* validate URL fields */
	if (url->mailbox == NULL || url->uid == 0 ||
	    url->search_program != NULL || url->uauth_rumpurl == NULL ||
	    url->uauth_mechanism == NULL) {
		*error_r = "Invalid URL: Must be a full URLAUTH URL";
		return FALSE;
	}

	/* check presence of userid */
	if (url->userid == NULL) {
		*error_r = "Invalid URLAUTH: Missing user name";
		return FALSE;
	}

	/* validate mechanism */
	if (strcasecmp(url->uauth_mechanism, "INTERNAL") != 0) {
		*error_r = t_strdup_printf("Unsupported URLAUTH mechanism: %s",
					   url->uauth_mechanism);
		return FALSE;
	}

	/* validate expiry time */
	if (url->uauth_expire != (time_t)-1) {
		time_t now = time(NULL);

		if (now > url->uauth_expire) {
			*error_r = t_strdup_printf("URLAUTH has expired");
			return FALSE;
		}
	}

	/* validate access */
	if (!imap_urlauth_check_access(uctx, url, ignore_unknown_access,
				       error_r))
		return FALSE;
	/* validate host:port */
	if (!imap_urlauth_check_hostport(uctx, url, error_r))
		return FALSE;
	return TRUE;
}

int imap_urlauth_fetch_parsed(struct imap_urlauth_context *uctx,
			      struct imap_url *url,
			      struct imap_msgpart_url **mpurl_r,
			      enum mail_error *error_code_r,
			      const char **error_r)
{
	struct mail_user *user = uctx->user;
	struct imap_msgpart_url *mpurl;
	struct mailbox *box;
	const char *error;
	unsigned char mailbox_key[IMAP_URLAUTH_KEY_LEN];
	int ret;

	*mpurl_r = NULL;
	*error_r = NULL;
	*error_code_r = MAIL_ERROR_NONE;

	/* check urlauth mechanism, access, userid and authority */
	if (!imap_urlauth_check(uctx, url, FALSE, error_r)) {
		*error_code_r = MAIL_ERROR_PARAMS;
		return 0;
	}

	/* validate target user */
	if (user->anonymous || strcmp(url->userid, user->username) != 0) {
		*error_r = t_strdup_printf("Not permitted to fetch URLAUTH for user %s",
					   url->userid);
		*error_code_r = MAIL_ERROR_PARAMS;
		return 0;
	}

	/* validate mailbox */
	if ((ret = imap_msgpart_url_create(user, url, &mpurl, &error)) < 0) {
		*error_r = t_strdup_printf("Invalid URLAUTH: %s", error);
		*error_code_r = MAIL_ERROR_PARAMS;
		return ret;
	}

	if ((ret = imap_msgpart_url_open_mailbox(mpurl, &box, error_code_r,
						 &error)) < 0) {
		*error_r = "Internal server error";
		imap_msgpart_url_free(&mpurl);
		return -1;
	}

	if (ret == 0) {
		/* RFC says: `If the mailbox cannot be identified, an
		   authorization token is calculated on the rump URL, using
		   random "plausible" keys (selected by the server) as needed,
		   before returning a validation failure. This prevents timing
		   attacks aimed at identifying mailbox names.' */
		random_fill(mailbox_key, sizeof(mailbox_key));
		(void)imap_urlauth_internal_verify(url->uauth_rumpurl,
			mailbox_key, url->uauth_token, url->uauth_token_size);

		*error_r = t_strdup_printf("Invalid URLAUTH: %s", error);
		imap_msgpart_url_free(&mpurl);
		return 0;
	}

	/* obtain mailbox key */
	ret = imap_urlauth_backend_get_mailbox_key(box, FALSE, mailbox_key,
						   error_r, error_code_r);
	if (ret < 0) {
		imap_msgpart_url_free(&mpurl);
		return -1;
	}

	if (ret == 0 ||
	    !imap_urlauth_internal_verify(url->uauth_rumpurl, mailbox_key,
					  url->uauth_token,
					  url->uauth_token_size)) {
		*error_r = "URLAUTH verification failed";
		*error_code_r = MAIL_ERROR_PERM;
		imap_msgpart_url_free(&mpurl);
		ret = 0;
	} else {
		ret = 1;
	}

	safe_memset(mailbox_key, 0, sizeof(mailbox_key));
	*mpurl_r = mpurl;
	return ret;
}

int imap_urlauth_fetch(struct imap_urlauth_context *uctx,
		       const char *urlauth, struct imap_msgpart_url **mpurl_r,
		       enum mail_error *error_code_r, const char **error_r)
{
	struct imap_url *url;
	enum imap_url_parse_flags url_flags = IMAP_URL_PARSE_ALLOW_URLAUTH;
	const char *error;

	/* validate URL */
	if (imap_url_parse(urlauth, NULL, url_flags, &url, &error) < 0) {
		*error_r = t_strdup_printf("Invalid URLAUTH: %s", error);
		*error_code_r = MAIL_ERROR_PARAMS;
		return 0;
	}

	return imap_urlauth_fetch_parsed(uctx, url, mpurl_r,
					 error_code_r, error_r);
}

int imap_urlauth_reset_mailbox_key(struct imap_urlauth_context *uctx ATTR_UNUSED,
				   struct mailbox *box)
{
	return imap_urlauth_backend_reset_mailbox_key(box);
}

int imap_urlauth_reset_all_keys(struct imap_urlauth_context *uctx)
{
	return imap_urlauth_backend_reset_all_keys(uctx->user);
}
