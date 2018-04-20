/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "login-common.h"
#include "hostpid.h"
#include "var-expand.h"
#include "settings-parser.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "master-service-ssl-settings.h"
#include "master-service-settings-cache.h"
#include "login-settings.h"

#include <stddef.h>
#include <unistd.h>

static bool login_settings_check(void *_set, pool_t pool, const char **error_r);

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct login_settings, name), NULL }

static const struct setting_define login_setting_defines[] = {
	DEF(SET_STR, login_trusted_networks),
	DEF(SET_STR, login_source_ips),
	DEF(SET_STR_VARS, login_greeting),
	DEF(SET_STR, login_log_format_elements),
	DEF(SET_STR, login_log_format),
	DEF(SET_STR, login_access_sockets),
	DEF(SET_STR_VARS, login_proxy_notify_path),
	DEF(SET_STR, login_plugin_dir),
	DEF(SET_STR, login_plugins),
	DEF(SET_TIME, login_proxy_max_disconnect_delay),
	DEF(SET_STR, director_username_hash),

	DEF(SET_STR, ssl_client_cert),
	DEF(SET_STR, ssl_client_key),
	DEF(SET_BOOL, ssl_require_crl),
	DEF(SET_BOOL, auth_ssl_require_client_cert),
	DEF(SET_BOOL, auth_ssl_username_from_cert),

	DEF(SET_STR, ssl_cert_md_algorithm),
	DEF(SET_UINT, ssl_verify_depth),

	DEF(SET_BOOL, disable_plaintext_auth),
	DEF(SET_BOOL, auth_verbose),
	DEF(SET_BOOL, auth_debug),
	DEF(SET_BOOL, verbose_proctitle),

	DEF(SET_BOOL, ssl_cert_info),
	DEF(SET_BOOL, ssl_cert_debug),

	DEF(SET_UINT, mail_max_userip_connections),

	SETTING_DEFINE_LIST_END
};

static const struct login_settings login_default_settings = {
	.login_trusted_networks = "",
	.login_source_ips = "",
	.login_greeting = PACKAGE_NAME" ready.",
	.login_log_format_elements = "user=<%u> method=%m rip=%r lip=%l mpid=%e %c session=<%{session}>",
	.login_log_format = "%$: %s",
	.login_access_sockets = "",
	.login_proxy_notify_path = "proxy-notify",
	.login_plugin_dir = MODULEDIR"/login",
	.login_plugins = "",
	.login_proxy_max_disconnect_delay = 0,
	.director_username_hash = "%u",

	.ssl_client_cert = "",
	.ssl_client_key = "",
	.ssl_require_crl = TRUE,
	.auth_ssl_require_client_cert = FALSE,
	.auth_ssl_username_from_cert = FALSE,

	.ssl_cert_md_algorithm = "sha1",
	.ssl_verify_depth = 9,

	.disable_plaintext_auth = TRUE,
	.auth_verbose = FALSE,
	.auth_debug = FALSE,
	.verbose_proctitle = FALSE,

	.mail_max_userip_connections = 10,

	.ssl_cert_info = FALSE,
	.ssl_cert_debug = FALSE
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

static struct master_service_settings_cache *set_cache;

/* <settings checks> */
static bool login_settings_check(void *_set, pool_t pool,
				 const char **error_r ATTR_UNUSED)
{
	struct login_settings *set = _set;

	set->log_format_elements_split =
		p_strsplit(pool, set->login_log_format_elements, " ");

	if (set->auth_debug_passwords)
		set->auth_debug = TRUE;
	if (set->auth_debug)
		set->auth_verbose = TRUE;
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
		{ '\0', NULL, "local_name" },
		{ '\0', NULL, NULL }
	};
	struct var_expand_table *tab;

	tab = t_malloc(sizeof(static_tab));
	memcpy(tab, static_tab, sizeof(static_tab));

	tab[0].value = net_ip2addr(&input->local_ip);
	tab[1].value = net_ip2addr(&input->remote_ip);
	tab[2].value = my_pid;
	tab[3].value = input->service;
	tab[4].value = input->local_name;
	return tab;
}

static void *
login_setting_dup(pool_t pool, const struct setting_parser_info *info,
		  const void *src_set)
{
	const char *error;
	void *dest;

	dest = settings_dup(info, src_set, pool);
	if (!settings_check(info, pool, dest, &error)) {
		const char *name = info->module_name;

		i_fatal("settings_check(%s) failed: %s",
			name != NULL ? name : "unknown", error);
	}
	return dest;
}

struct login_settings *
login_settings_read(pool_t pool,
		    const struct ip_addr *local_ip,
		    const struct ip_addr *remote_ip,
		    const char *local_name,
		    const struct master_service_ssl_settings **ssl_set_r,
		    void ***other_settings_r)
{
	struct master_service_settings_input input;
	const char *error;
	const struct setting_parser_context *parser;
	void *const *cache_sets;
	void **sets;
	unsigned int i, count;

	i_zero(&input);
	input.roots = login_set_roots;
	input.module = login_binary->process_name;
	input.service = login_binary->protocol;
	input.local_name = local_name;

	if (local_ip != NULL)
		input.local_ip = *local_ip;
	if (remote_ip != NULL)
		input.remote_ip = *remote_ip;

	if (set_cache == NULL) {
		set_cache = master_service_settings_cache_init(master_service,
							       input.module,
							       input.service);
		/* lookup filters

		   this is only enabled if service_count > 1 because otherwise
		   login process will process only one request and this is only
		   useful when more than one request is processed.
		*/
		if (master_service_get_service_count(master_service) > 1)
			master_service_settings_cache_init_filter(set_cache);
	}

	if (master_service_settings_cache_read(set_cache, &input, NULL,
					       &parser, &error) < 0)
		i_fatal("Error reading configuration: %s", error);

	cache_sets = master_service_settings_parser_get_others(master_service, parser);
	for (count = 0; input.roots[count] != NULL; count++) ;
	i_assert(cache_sets[count] == NULL);
	sets = p_new(pool, void *, count + 1);
	for (i = 0; i < count; i++)
		sets[i] = login_setting_dup(pool, input.roots[i], cache_sets[i]);

	settings_var_expand(&login_setting_parser_info, sets[0], pool,
			    login_set_var_expand_table(&input));

	*ssl_set_r =
		login_setting_dup(pool, &master_service_ssl_setting_parser_info,
				  settings_parser_get_list(parser)[1]);
	*other_settings_r = sets + 1;
	return sets[0];
}

void login_settings_deinit(void)
{
	if (set_cache != NULL)
		master_service_settings_cache_deinit(&set_cache);
}
