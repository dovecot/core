/* Copyright (c) 2005-2009 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "hostpid.h"
#include "var-expand.h"
#include "settings-parser.h"
#include "master-service-settings.h"
#include "login-settings.h"

#include <stddef.h>
#include <unistd.h>

static bool login_settings_check(void *_set, pool_t pool, const char **error_r);

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct login_settings, name), NULL }

static const struct setting_define login_setting_defines[] = {
	DEF(SET_STR, login_trusted_networks),
	DEF(SET_STR_VARS, login_greeting),
	DEF(SET_STR, login_log_format_elements),
	DEF(SET_STR, login_log_format),

	DEF(SET_ENUM, ssl),
	DEF(SET_STR, ssl_ca),
	DEF(SET_STR, ssl_cert),
	DEF(SET_STR, ssl_key),
	DEF(SET_STR, ssl_key_password),
	DEF(SET_STR, ssl_parameters_file),
	DEF(SET_STR, ssl_cipher_list),
	DEF(SET_STR, ssl_cert_username_field),
	DEF(SET_BOOL, ssl_verify_client_cert),
	DEF(SET_BOOL, ssl_require_client_cert),
	DEF(SET_BOOL, ssl_username_from_cert),
	DEF(SET_BOOL, verbose_ssl),

	DEF(SET_BOOL, disable_plaintext_auth),
	DEF(SET_BOOL, verbose_auth),
	DEF(SET_BOOL, auth_debug),
	DEF(SET_BOOL, verbose_proctitle),

	DEF(SET_UINT, mail_max_userip_connections),

	SETTING_DEFINE_LIST_END
};

static const struct login_settings login_default_settings = {
	.login_trusted_networks = "",
	.login_greeting = PACKAGE_NAME" ready.",
	.login_log_format_elements = "user=<%u> method=%m rip=%r lip=%l %c",
	.login_log_format = "%$: %s",

	.ssl = "yes:no:required",
	.ssl_ca = "",
	.ssl_cert = "",
	.ssl_key = "",
	.ssl_key_password = "",
	.ssl_parameters_file = "ssl-parameters.dat",
	.ssl_cipher_list = "ALL:!LOW:!SSLv2:!EXP:!aNULL",
	.ssl_cert_username_field = "commonName",
	.ssl_verify_client_cert = FALSE,
	.ssl_require_client_cert = FALSE,
	.ssl_username_from_cert = FALSE,
	.verbose_ssl = FALSE,

	.disable_plaintext_auth = TRUE,
	.verbose_auth = FALSE,
	.auth_debug = FALSE,
	.verbose_proctitle = FALSE,

	.mail_max_userip_connections = 10
};

const struct setting_parser_info login_setting_parser_info = {
	.module_name = "login",
	.defines = login_setting_defines,
	.defaults = &login_default_settings,

	.type_offset = (size_t)-1,
	.struct_size = sizeof(struct login_settings),

	.parent_offset = (size_t)-1,

	.check_func = login_settings_check
};

static const struct setting_parser_info *default_login_set_roots[] = {
	&login_setting_parser_info,
	NULL
};

const struct setting_parser_info **login_set_roots = default_login_set_roots;

/* <settings checks> */
static int ssl_settings_check(void *_set ATTR_UNUSED, const char **error_r)
{
	struct login_settings *set = _set;

#ifndef HAVE_SSL
	*error_r = t_strdup_printf("SSL support not compiled in but ssl=%s",
				   set->ssl);
	return FALSE;
#else
	if (*set->ssl_cert == '\0') {
		*error_r = "ssl enabled, but ssl_cert not set";
		return FALSE;
	}
	if (*set->ssl_key == '\0') {
		*error_r = "ssl enabled, but ssl_key not set";
		return FALSE;
	}
	if (set->ssl_verify_client_cert && *set->ssl_ca == '\0') {
		*error_r = "ssl_verify_client_cert set, but ssl_ca not";
		return FALSE;
	}
	return TRUE;
#endif
}

static bool login_settings_check(void *_set, pool_t pool, const char **error_r)
{
	struct login_settings *set = _set;

	set->log_format_elements_split =
		p_strsplit(pool, set->login_log_format_elements, " ");

	if (set->ssl_require_client_cert || set->ssl_username_from_cert) {
		/* if we require valid cert, make sure we also ask for it */
		set->ssl_verify_client_cert = TRUE;
	}

	if (strcmp(set->ssl, "no") == 0) {
		/* disabled */
	} else if (strcmp(set->ssl, "yes") == 0) {
		if (!ssl_settings_check(set, error_r))
			return FALSE;
	} else if (strcmp(set->ssl, "required") == 0) {
		if (!ssl_settings_check(set, error_r))
			return FALSE;
		set->disable_plaintext_auth = TRUE;
	} else {
		*error_r = t_strdup_printf("Unknown ssl setting value: %s",
					   set->ssl);
		return FALSE;
	}
	return TRUE;
}
/* </settings checks> */

static const struct var_expand_table *
login_set_var_expand_table(const struct master_service_settings_input *input)
{
	static struct var_expand_table static_tab[] = {
		{ 'l', NULL, "lip" },
		{ 'r', NULL, "rip" },
		{ 'p', NULL, "pid" },
		{ 's', NULL, "service" },
		{ '\0', NULL, "hostname" },
		{ '\0', NULL, NULL }
	};
	struct var_expand_table *tab;

	tab = t_malloc(sizeof(static_tab));
	memcpy(tab, static_tab, sizeof(static_tab));

	tab[0].value = net_ip2addr(&input->local_ip);
	tab[1].value = net_ip2addr(&input->remote_ip);
	tab[2].value = my_pid;
	tab[3].value = input->service;
	tab[4].value = my_hostname;
	return tab;
}

struct login_settings *
login_settings_read(struct master_service *service, pool_t pool,
		    const struct ip_addr *local_ip,
		    const struct ip_addr *remote_ip,
		    const char *local_host,
		    void ***other_settings_r)
{
	struct master_service_settings_input input;
	const char *error;
	void **sets;
	unsigned int i;

	memset(&input, 0, sizeof(input));
	input.roots = login_set_roots;
	input.module = login_process_name;
	input.service = login_protocol;
	input.local_host = local_host;

	if (local_ip != NULL)
		input.local_ip = *local_ip;
	if (remote_ip != NULL)
		input.remote_ip = *remote_ip;

	/* this function always clears the previous settings pool. since we're
	   doing per-connection lookups, we always need to duplicate the
	   settings using another pool. */
	if (master_service_settings_read(service, &input, &error) < 0)
		i_fatal("Error reading configuration: %s", error);

	sets = master_service_settings_get_others(service);
	for (i = 0; sets[i] != NULL; i++) {
		sets[i] = settings_dup(input.roots[i], sets[i], pool);
		if (!settings_check(input.roots[i], pool, sets[i], &error)) {
			const char *name = input.roots[i]->module_name;
			i_fatal("settings_check(%s) failed: %s",
				name != NULL ? name : "unknown", error);
		}
	}

	settings_var_expand(&login_setting_parser_info, sets[0], pool,
			    login_set_var_expand_table(&input));

	*other_settings_r = sets + 1;
	return sets[0];
}
