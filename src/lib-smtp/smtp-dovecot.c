/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "auth-proxy.h"
#include "smtp-common.h"
#include "smtp-reply.h"
#include "smtp-server.h"
#include "smtp-dovecot.h"

bool smtp_reply_code_is_proxy_redirect(unsigned int code, const char *enh_code)
{
	return (code == 550 && enh_code != NULL &&
		strcmp(enh_code, SMTP_PROXY_REDIRECT_ENH_CODE_STR) == 0);
}

bool smtp_reply_is_proxy_redirect(const struct smtp_reply *reply)
{
	return smtp_reply_code_equals(reply, SMTP_PROXY_REDIRECT_CODE,
				      SMTP_PROXY_REDIRECT_ENH_CODE);
}

int smtp_proxy_redirect_parse(const char *target, const char **destuser_r,
			      const char **host_r, struct ip_addr *ip_r,
			      in_port_t *port_r, const char **error_r)
{
	const char *pend;

	*error_r = NULL;

	/* Skip <address> part of the reply if present (RCPT reply) */
	pend = strchr(target, ' ');
	if (*target == '<') {
		if (pend == NULL) {
			*error_r = "Invalid path in redirect response";
			return -1;
		}
		target = pend + 1;
		pend = strchr(target, ' ');
	}
	if (pend != NULL)
		target = t_strdup_until(target, pend);

	if (!auth_proxy_parse_redirect(target, destuser_r, host_r,
				       ip_r, port_r)) {
		*error_r = "Invalid redirect data";
		return -1;
	}
	return 0;
}

static const char *
smtp_create_redirect_reply(const struct smtp_proxy_redirect *predir,
			   in_port_t default_port)
{
	string_t *referral = t_str_new(128);

	if (predir->username != NULL)
		str_printfa(referral, "%s@", predir->username);
	if (predir->port == default_port)
		str_append(referral, predir->host);
	else
		str_printfa(referral, "%s:%u", predir->host, predir->port);
	return str_c(referral);
}

void smtp_server_reply_redirect(struct smtp_server_cmd_ctx *cmd,
				in_port_t default_port,
				const struct smtp_proxy_redirect *predir)
{
	smtp_server_reply(cmd, SMTP_PROXY_REDIRECT_CODE,
			  SMTP_PROXY_REDIRECT_ENH_CODE_STR,
			  "%s Referral",
			  smtp_create_redirect_reply(predir, default_port));
}

void smtp_server_recipient_reply_redirect(
	struct smtp_server_recipient *rcpt, in_port_t default_port,
	const struct smtp_proxy_redirect *predir)
{
	smtp_server_recipient_reply(
		rcpt, SMTP_PROXY_REDIRECT_CODE,
		SMTP_PROXY_REDIRECT_ENH_CODE_STR, "%s Referral",
		smtp_create_redirect_reply(predir, default_port));
}
