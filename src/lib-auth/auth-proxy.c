/* Copyright (c) 2021 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "settings-parser.h"
#include "auth-proxy.h"

static const char *maybe_strdup(pool_t pool, const char *str)
{
	return pool == NULL ? str : p_strdup(pool, str);
}

int auth_proxy_settings_parse(struct auth_proxy_settings *set, pool_t pool,
			      const char *key, const char *value,
			      const char **error_r)
{
	if (strcmp(key, "proxy") == 0)
		set->proxy = TRUE;
	else if (strcmp(key, "host") == 0) {
		if (value[0] == '\0') {
			*error_r = "Empty host";
			return -1;
		}
		set->host = maybe_strdup(pool, value);
	} else if (strcmp(key, "hostip") == 0) {
		if (value[0] != '\0' && net_addr2ip(value, &set->host_ip) < 0) {
			*error_r = "Not a valid IP address";
			return -1;
		}
	} else if (strcmp(key, "port") == 0) {
		if (net_str2port(value, &set->port) < 0) {
			*error_r = "Not a valid port number";
			return -1;
		}
	} else if (strcmp(key, "ssl") == 0) {
		set->ssl_flags |= AUTH_PROXY_SSL_FLAG_YES;
		if (strcmp(value, "any-cert") == 0)
			set->ssl_flags |= AUTH_PROXY_SSL_FLAG_ANY_CERT;
	} else if (strcmp(key, "starttls") == 0) {
		set->ssl_flags |= AUTH_PROXY_SSL_FLAG_YES |
			AUTH_PROXY_SSL_FLAG_STARTTLS;
		if (strcmp(value, "any-cert") == 0)
			set->ssl_flags |= AUTH_PROXY_SSL_FLAG_ANY_CERT;
	} else if (strcmp(key, "source_ip") == 0) {
		if (value[0] != '\0' &&
		    net_addr2ip(value, &set->source_ip) < 0) {
			*error_r = "Not a valid IP address";
			return -1;
		}
	} else if (strcmp(key, "destuser") == 0)
		set->username = maybe_strdup(pool, value);
	else if (strcmp(key, "master") == 0) {
		/* ignore empty master field */
		if (*value != '\0')
			set->master_user = maybe_strdup(pool, value);
	} else if (strcmp(key, "pass") == 0)
		set->password = maybe_strdup(pool, value);
	else if (strcmp(key, "proxy_mech") == 0)
		set->sasl_mechanism = maybe_strdup(pool, value);
	else if (strcmp(key, "proxy_timeout") == 0) {
		/* backwards compatibility: plain number is seconds */
		if (str_to_uint(value, &set->timeout_msecs) == 0)
			set->timeout_msecs *= 1000;
		else if (settings_get_time_msecs(value,
				&set->timeout_msecs, error_r) < 0) {
			return -1;
		}
	} else if (strcmp(key, "proxy_nopipelining") == 0)
		set->nopipelining = TRUE;
	else if (strcmp(key, "proxy_noauth") == 0)
		set->noauth = TRUE;
	else if (strcmp(key, "proxy_not_trusted") == 0)
		set->remote_not_trusted = TRUE;
	else if (strcmp(key, "proxy_redirect_reauth") == 0)
		set->redirect_reauth = TRUE;
	else
		return 0;
	return 1;
}

bool auth_proxy_parse_redirect(const char *target,
			       const char **destuser_r,
			       const char **host_r, struct ip_addr *ip_r,
			       in_port_t *port_r)
{
	const char *p;

	p = strrchr(target, '@');
	if (p == NULL)
		*destuser_r = NULL;
	else {
		*destuser_r = t_strdup_until(target, p);
		target = p+1;
	}
	if (net_str2hostport(target, 0, host_r, port_r) < 0)
		return FALSE;
	if (net_addr2ip(*host_r, ip_r) < 0)
		return FALSE;
	return TRUE;
}
