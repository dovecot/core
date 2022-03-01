/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "uri-util.h"
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

int smtp_proxy_redirect_parse(const char *resp, const char **destuser_r,
			      const char **host_r, struct ip_addr *ip_r,
			      in_port_t *port_r, const char **error_r)
{
	const char *pend;

	*destuser_r = NULL;
	*host_r = NULL;
	i_zero(ip_r);
	*port_r = 0;
	*error_r = NULL;

	/* Skip <address> part of the reply if present (RCPT reply) */
	pend = strchr(resp, ' ');
	if (*resp == '<') {
		if (pend == NULL || *(pend - 1) != '>') {
			*error_r = "Invalid path in redirect response";
			return -1;
		}
		resp = pend + 1;
	}

	struct uri_parser parser;
	const char *destuser;
	struct uri_authority uri_auth;

	i_zero(&parser);
	parser.pool = pool_datastack_create();
	parser.begin = parser.cur = (const unsigned char *)resp;
	parser.end = parser.begin + strlen(resp);
	parser.parse_prefix = TRUE;

	if (uri_parse_host_authority(&parser, &uri_auth) < 0 ||
	    !uri_data_decode(&parser, uri_auth.enc_userinfo, NULL, &destuser)) {
		*error_r = parser.error;
		return -1;

	}
	if (*parser.cur != '\0' && *parser.cur != ' ') {
		*error_r = t_strdup_printf(
			"Invalid character %s in redirect target",
			uri_char_sanitize(*parser.cur));
		return -1;
	}

	*destuser_r = destuser;
	*host_r = uri_auth.host.name;
	*ip_r = uri_auth.host.ip;
	*port_r = uri_auth.port;
	return 0;
}

static const char *
smtp_create_redirect_reply(const struct smtp_proxy_redirect *predir,
			   in_port_t default_port)
{
	string_t *referral = t_str_new(128);

	struct uri_host host = {
		.name = predir->host,
		.ip = predir->host_ip,
	};
	if (predir->username != NULL)
		uri_append_userinfo(referral, predir->username);
	uri_append_host(referral, &host);
	if (predir->port != default_port)
		uri_append_port(referral, predir->port);

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
