/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "var-expand.h"
#include "settings-parser.h"
#include "service-settings.h"
#include "mail-storage-settings.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "master-service-ssl-settings.h"
#include "iostream-ssl.h"
#include "doveadm-settings.h"

ARRAY_TYPE(doveadm_setting_root) doveadm_setting_roots;
bool doveadm_verbose_proctitle;

static pool_t doveadm_settings_pool = NULL;

static bool doveadm_settings_check(void *_set, pool_t pool, const char **error_r);

/* <settings checks> */
static struct file_listener_settings doveadm_unix_listeners_array[] = {
	{ "doveadm-server", 0600, "", "" }
};
static struct file_listener_settings *doveadm_unix_listeners[] = {
	&doveadm_unix_listeners_array[0]
};
static buffer_t doveadm_unix_listeners_buf = {
	{ { doveadm_unix_listeners, sizeof(doveadm_unix_listeners) } }
};
/* </settings checks> */

struct service_settings doveadm_service_settings = {
	.name = "doveadm",
	.protocol = "",
	.type = "",
	.executable = "doveadm-server",
	.user = "",
	.group = "",
	.privileged_group = "",
	.extra_groups = "$default_internal_group",
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 0,
	.client_limit = 1,
	.service_count = 1,
	.idle_kill = 0,
	.vsz_limit = UOFF_T_MAX,

	.unix_listeners = { { &doveadm_unix_listeners_buf,
			      sizeof(doveadm_unix_listeners[0]) } },
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct doveadm_settings)

static const struct setting_define doveadm_setting_defines[] = {
	DEF(STR, base_dir),
	DEF(STR, libexec_dir),
	DEF(STR, mail_plugins),
	DEF(STR, mail_plugin_dir),
	DEF(STR_VARS, mail_temp_dir),
	DEF(BOOL, auth_debug),
	DEF(STR, auth_socket_path),
	DEF(STR, doveadm_socket_path),
	DEF(UINT, doveadm_worker_count),
	DEF(IN_PORT, doveadm_port),
	{ .type = SET_ALIAS, .key = "doveadm_proxy_port" },
	DEF(ENUM, doveadm_ssl),
	DEF(STR, doveadm_username),
	DEF(STR, doveadm_password),
	DEF(STR, doveadm_allowed_commands),
	DEF(STR, dsync_alt_char),
	DEF(STR, dsync_remote_cmd),
	DEF(STR, director_username_hash),
	DEF(STR, doveadm_api_key),
	DEF(STR, dsync_features),
	DEF(UINT, dsync_commit_msgs_interval),
	DEF(STR, doveadm_http_rawlog_dir),
	DEF(STR, dsync_hashed_headers),

	{ .type = SET_STRLIST, .key = "plugin",
	  .offset = offsetof(struct doveadm_settings, plugin_envs) },

	SETTING_DEFINE_LIST_END
};

const struct doveadm_settings doveadm_default_settings = {
	.base_dir = PKG_RUNDIR,
	.libexec_dir = PKG_LIBEXECDIR,
	.mail_plugins = "",
	.mail_plugin_dir = MODULEDIR,
	.mail_temp_dir = "/tmp",
	.auth_debug = FALSE,
	.auth_socket_path = "auth-userdb",
	.doveadm_socket_path = "doveadm-server",
	.doveadm_worker_count = 0,
	.doveadm_port = 0,
	.doveadm_ssl = "no:ssl:starttls",
	.doveadm_username = "doveadm",
	.doveadm_password = "",
	.doveadm_allowed_commands = "",
	.dsync_alt_char = "_",
	.dsync_remote_cmd = "ssh -l%{login} %{host} doveadm dsync-server -u%u -U",
	.dsync_features = "",
	.dsync_hashed_headers = "Date Message-ID",
	.dsync_commit_msgs_interval = 100,
	.director_username_hash = "%Lu",
	.doveadm_api_key = "",
	.doveadm_http_rawlog_dir = "",

	.plugin_envs = ARRAY_INIT
};

static const struct setting_parser_info *doveadm_setting_dependencies[] = {
	&mail_user_setting_parser_info,
	NULL
};

const struct setting_parser_info doveadm_setting_parser_info = {
	.module_name = "doveadm",
	.defines = doveadm_setting_defines,
	.defaults = &doveadm_default_settings,

	.type_offset = SIZE_MAX,
	.struct_size = sizeof(struct doveadm_settings),

	.parent_offset = SIZE_MAX,
	.check_func = doveadm_settings_check,
	.dependencies = doveadm_setting_dependencies
};

struct doveadm_settings *doveadm_settings;
const struct master_service_settings *service_set;

static void
fix_base_path(struct doveadm_settings *set, pool_t pool, const char **str)
{
	if (*str != NULL && **str != '\0' && **str != '/')
		*str = p_strconcat(pool, set->base_dir, "/", *str, NULL);
}

/* <settings checks> */
struct dsync_feature_list {
	const char *name;
	enum dsync_features num;
};

static const struct dsync_feature_list dsync_feature_list[] = {
	{ "empty-header-workaround", DSYNC_FEATURE_EMPTY_HDR_WORKAROUND },
	{ NULL, 0 }
};

static int
dsync_settings_parse_features(struct doveadm_settings *set,
			      const char **error_r)
{
	enum dsync_features features = 0;
	const struct dsync_feature_list *list;
	const char *const *str;

	str = t_strsplit_spaces(set->dsync_features, " ,");
	for (; *str != NULL; str++) {
		list = dsync_feature_list;
		for (; list->name != NULL; list++) {
			if (strcasecmp(*str, list->name) == 0) {
				features |= list->num;
				break;
			}
		}
		if (list->name == NULL) {
			*error_r = t_strdup_printf("dsync_features: "
				"Unknown feature: %s", *str);
			return -1;
		}
	}
	set->parsed_features = features;
	return 0;
}

static bool doveadm_settings_check(void *_set, pool_t pool ATTR_UNUSED,
				   const char **error_r)
{
	struct doveadm_settings *set = _set;

#ifndef CONFIG_BINARY
	fix_base_path(set, pool, &set->auth_socket_path);
	fix_base_path(set, pool, &set->doveadm_socket_path);
#endif
	if (*set->dsync_hashed_headers == '\0') {
		*error_r = "dsync_hashed_headers must not be empty";
		return FALSE;
	}
	if (*set->dsync_alt_char == '\0') {
		*error_r = "dsync_alt_char must not be empty";
		return FALSE;
	}
	if (dsync_settings_parse_features(set, error_r) != 0)
		return FALSE;
	return TRUE;
}
/* </settings checks> */

const struct master_service_ssl_settings *doveadm_ssl_set = NULL;

void doveadm_get_ssl_settings(struct ssl_iostream_settings *set_r, pool_t pool)
{
	master_service_ssl_client_settings_to_iostream_set(doveadm_ssl_set,
							   pool, set_r);
}

void doveadm_settings_expand(struct doveadm_settings *set, pool_t pool)
{
	struct var_expand_table tab[] = { { '\0', NULL, NULL } };
	const char *error;

	if (settings_var_expand(&doveadm_setting_parser_info, set,
				pool, tab, &error) <= 0)
		i_fatal("Failed to expand settings: %s", error);
}

void doveadm_read_settings(void)
{
	static const struct setting_parser_info *default_set_roots[] = {
		&master_service_ssl_setting_parser_info,
		&doveadm_setting_parser_info,
	};
	struct master_service_settings_input input;
	struct master_service_settings_output output;
	const struct doveadm_settings *set;
	struct doveadm_setting_root *root;
	ARRAY(const struct setting_parser_info *) set_roots;
	ARRAY_TYPE(const_string) module_names;
	void **sets;
	const char *error;

	t_array_init(&set_roots, N_ELEMENTS(default_set_roots) +
		     array_count(&doveadm_setting_roots) + 1);
	array_append(&set_roots, default_set_roots,
		     N_ELEMENTS(default_set_roots));
	t_array_init(&module_names, 4);
	array_foreach_modifiable(&doveadm_setting_roots, root) {
		array_push_back(&module_names, &root->info->module_name);
		array_push_back(&set_roots, &root->info);
	}
	array_append_zero(&module_names);
	array_append_zero(&set_roots);

	i_zero(&input);
	input.roots = array_front(&set_roots);
	input.module = "doveadm";
	input.extra_modules = array_front(&module_names);
	input.service = "doveadm";
	input.preserve_user = TRUE;
	input.preserve_home = TRUE;
	if (master_service_settings_read(master_service, &input,
					 &output, &error) < 0)
		i_fatal("Error reading configuration: %s", error);

	doveadm_settings_pool = pool_alloconly_create("doveadm settings", 1024);
	service_set = master_service_settings_get(master_service);
	service_set = settings_dup(&master_service_setting_parser_info,
				   service_set, doveadm_settings_pool);
	doveadm_verbose_proctitle = service_set->verbose_proctitle;

	sets = master_service_settings_get_others(master_service);
	set = sets[1];
	doveadm_settings = settings_dup(&doveadm_setting_parser_info, set,
					doveadm_settings_pool);
	doveadm_ssl_set = settings_dup(&master_service_ssl_setting_parser_info,
				       master_service_ssl_settings_get(master_service),
				       doveadm_settings_pool);
	doveadm_settings_expand(doveadm_settings, doveadm_settings_pool);
	doveadm_settings->parsed_features = set->parsed_features; /* copy this value by hand */

	array_foreach_modifiable(&doveadm_setting_roots, root) {
		unsigned int idx =
			array_foreach_idx(&doveadm_setting_roots, root);
		root->settings = settings_dup(root->info, sets[2+idx],
					      doveadm_settings_pool);
	}
}

void doveadm_setting_roots_add(const struct setting_parser_info *info)
{
	struct doveadm_setting_root *root;

	root = array_append_space(&doveadm_setting_roots);
	root->info = info;
}

void *doveadm_setting_roots_get_settings(const struct setting_parser_info *info)
{
	const struct doveadm_setting_root *root;

	array_foreach(&doveadm_setting_roots, root) {
		if (root->info == info)
			return root->settings;
	}
	i_panic("Failed to find settings for module %s", info->module_name);
}

void doveadm_settings_init(void)
{
	i_array_init(&doveadm_setting_roots, 8);
}

void doveadm_settings_deinit(void)
{
	array_free(&doveadm_setting_roots);
	pool_unref(&doveadm_settings_pool);
}
