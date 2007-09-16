/* Copyright (c) 2002-2007 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "hostpid.h"
#include "str.h"
#include "str-sanitize.h"
#include "var-expand.h"
#include "ssl-proxy.h"
#include "client-common.h"

#include <stdlib.h>

static const struct var_expand_table *
get_var_expand_table(struct client *client)
{
	static struct var_expand_table static_tab[] = {
		{ 'u', NULL },
		{ 'n', NULL },
		{ 'd', NULL },
		{ 's', NULL },
		{ 'h', NULL },
		{ 'l', NULL },
		{ 'r', NULL },
		{ 'p', NULL },
		{ 'm', NULL },
		{ 'a', NULL },
		{ 'b', NULL },
		{ 'c', NULL },
		{ '\0', NULL }
	};
	struct var_expand_table *tab;

	tab = t_malloc(sizeof(static_tab));
	memcpy(tab, static_tab, sizeof(static_tab));

	if (client->virtual_user != NULL) {
		tab[0].value = client->virtual_user;
		tab[1].value = t_strcut(client->virtual_user, '@');
		tab[2].value = strchr(client->virtual_user, '@');
		if (tab[2].value != NULL) tab[2].value++;
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
	} else {
		tab[11].value = client->proxy != NULL &&
			ssl_proxy_is_handshaked(client->proxy) ? "TLS" :
			"TLS handshaking";
	}

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

void client_syslog(struct client *client, const char *msg)
{
	static struct var_expand_table static_tab[3] = {
		{ 's', NULL },
		{ '$', NULL },
		{ '\0', NULL }
	};
	const struct var_expand_table *var_expand_table;
	struct var_expand_table *tab;
	const char *p, *const *e;
	string_t *str;

	t_push();
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
	i_info("%s", str_c(str));

	t_pop();
}
