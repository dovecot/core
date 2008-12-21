/* Copyright (c) 2002-2008 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "hostpid.h"
#include "llist.h"
#include "str.h"
#include "str-sanitize.h"
#include "var-expand.h"
#include "ssl-proxy.h"
#include "client-common.h"

#include <stdlib.h>

struct client *clients = NULL;
static unsigned int clients_count = 0;

void client_link(struct client *client)
{
	DLLIST_PREPEND(&clients, client);
	clients_count++;
}

void client_unlink(struct client *client)
{
	i_assert(clients_count > 0);

	clients_count--;
	DLLIST_REMOVE(&clients, client);
}

unsigned int clients_get_count(void)
{
	return clients_count;
}

static const struct var_expand_table *
get_var_expand_table(struct client *client)
{
	static struct var_expand_table static_tab[] = {
		{ 'u', NULL, "user" },
		{ 'n', NULL, "username" },
		{ 'd', NULL, "domain" },
		{ 's', NULL, "service" },
		{ 'h', NULL, "home" },
		{ 'l', NULL, "lip" },
		{ 'r', NULL, "rip" },
		{ 'p', NULL, "pid" },
		{ 'm', NULL, "mech" },
		{ 'a', NULL, "lport" },
		{ 'b', NULL, "rport" },
		{ 'c', NULL, "secured" },
		{ 'k', NULL, "ssl_security" },
		{ 'e', NULL, "mail_pid" },
		{ '\0', NULL, NULL }
	};
	struct var_expand_table *tab;
	unsigned int i;

	tab = t_malloc(sizeof(static_tab));
	memcpy(tab, static_tab, sizeof(static_tab));

	if (client->virtual_user != NULL) {
		tab[0].value = client->virtual_user;
		tab[1].value = t_strcut(client->virtual_user, '@');
		tab[2].value = strchr(client->virtual_user, '@');
		if (tab[2].value != NULL) tab[2].value++;

		for (i = 0; i < 3; i++)
			tab[i].value = str_sanitize(tab[i].value, 80);
	}
	tab[3].value = login_protocol;
	tab[4].value = getenv("HOME");
	tab[5].value = net_ip2addr(&client->local_ip);
	tab[6].value = net_ip2addr(&client->ip);
	tab[7].value = my_pid;
	tab[8].value = client->auth_mech_name == NULL ? NULL :
		str_sanitize(client->auth_mech_name, MAX_MECH_NAME);
	tab[9].value = dec2str(client->local_port);
	tab[10].value = dec2str(client->remote_port);
	if (!client->tls) {
		tab[11].value = client->secured ? "secured" : NULL;
		tab[12].value = "";
	} else {
		const char *ssl_state = ssl_proxy_is_handshaked(client->proxy) ?
			"TLS" : "TLS handshaking";
		const char *ssl_error = ssl_proxy_get_last_error(client->proxy);

		tab[11].value = ssl_error == NULL ? ssl_state :
			t_strdup_printf("%s: %s", ssl_state, ssl_error);
		tab[12].value = ssl_proxy_get_security_string(client->proxy);
	}
	tab[13].value = dec2str(client->mail_pid);

	return tab;
}

static bool have_key(const struct var_expand_table *table, const char *str)
{
	char key;
	unsigned int i;

	key = var_get_key(str);
	for (i = 0; table[i].key != '\0'; i++) {
		if (table[i].key == key) {
			return table[i].value != NULL &&
				table[i].value[0] != '\0';
		}
	}
	return FALSE;
}

static const char *
client_get_log_str(struct client *client, const char *msg)
{
	static struct var_expand_table static_tab[3] = {
		{ 's', NULL, NULL },
		{ '$', NULL, NULL },
		{ '\0', NULL, NULL }
	};
	const struct var_expand_table *var_expand_table;
	struct var_expand_table *tab;
	const char *p, *const *e;
	string_t *str;

	var_expand_table = get_var_expand_table(client);

	tab = t_malloc(sizeof(static_tab));
	memcpy(tab, static_tab, sizeof(static_tab));

	str = t_str_new(256);
	for (e = log_format_elements; *e != NULL; e++) {
		for (p = *e; *p != '\0'; p++) {
			if (*p != '%' || p[1] == '\0')
				continue;

			p++;
			if (have_key(var_expand_table, p)) {
				if (str_len(str) > 0)
					str_append(str, ", ");
				var_expand(str, *e, var_expand_table);
				break;
			}
		}
	}

	tab[0].value = t_strdup(str_c(str));
	tab[1].value = msg;
	str_truncate(str, 0);

	var_expand(str, log_format, tab);
	return str_c(str);
}

void client_syslog(struct client *client, const char *msg)
{
	T_BEGIN {
		i_info("%s", client_get_log_str(client, msg));
	} T_END;
}

void client_syslog_err(struct client *client, const char *msg)
{
	T_BEGIN {
		i_error("%s", client_get_log_str(client, msg));
	} T_END;
}

bool client_is_trusted(struct client *client)
{
	const char *const *net;
	struct ip_addr net_ip;
	unsigned int bits;

	if (trusted_networks == NULL)
		return FALSE;

	net = t_strsplit_spaces(trusted_networks, ", ");
	for (; *net != NULL; net++) {
		if (net_parse_range(*net, &net_ip, &bits) < 0) {
			i_error("login_trusted_networks: "
				"Invalid network '%s'", *net);
			break;
		}

		if (net_is_in_network(&client->ip, &net_ip, bits))
			return TRUE;
	}
	return FALSE;
}

const char *client_get_extra_disconnect_reason(struct client *client)
{
	if (ssl_require_client_cert && client->proxy != NULL) {
		if (ssl_proxy_has_broken_client_cert(client->proxy))
			return "(client sent an invalid cert)";
		if (!ssl_proxy_has_valid_client_cert(client->proxy))
			return "(client didn't send a cert)";
	}

	if (client->auth_attempts == 0)
		return "(no auth attempts)";

	/* some auth attempts without SSL/TLS */
	if (client->auth_tried_disabled_plaintext)
		return "(tried to use disabled plaintext auth)";
	if (ssl_require_client_cert)
		return "(cert required, client didn't start TLS)";

	return t_strdup_printf("(auth failed, %u attempts)",
			       client->auth_attempts);
}
