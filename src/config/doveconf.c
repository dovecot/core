/* Copyright (c) 2005-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "abspath.h"
#include "module-dir.h"
#include "env-util.h"
#include "ostream.h"
#include "str.h"
#include "strescape.h"
#include "settings-parser.h"
#include "master-service.h"
#include "all-settings.h"
#include "sysinfo-get.h"
#include "config-connection.h"
#include "config-parser.h"
#include "config-request.h"
#include "dovecot-version.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sysexits.h>

struct prefix_stack {
	unsigned int prefix_idx;
	unsigned int str_pos;
};
ARRAY_DEFINE_TYPE(prefix_stack, struct prefix_stack);

struct config_dump_human_context {
	pool_t pool;
	string_t *list_prefix;
	ARRAY_TYPE(const_string) strings;
	ARRAY_TYPE(const_string) errors;
	struct config_export_context *export_ctx;

	unsigned int list_prefix_sent:1;
};

#define LIST_KEY_PREFIX "\001"
#define UNIQUE_KEY_SUFFIX "\xff"

static const char *indent_str = "                              !!!!";

static void
config_request_get_strings(const char *key, const char *value,
			   enum config_key_type type, void *context)
{
	struct config_dump_human_context *ctx = context;
	const char *p;

	switch (type) {
	case CONFIG_KEY_NORMAL:
		value = p_strdup_printf(ctx->pool, "%s=%s", key, value);
		break;
	case CONFIG_KEY_LIST:
		value = p_strdup_printf(ctx->pool, LIST_KEY_PREFIX"%s=%s",
					key, value);
		break;
	case CONFIG_KEY_UNIQUE_KEY:
		p = strrchr(key, '/');
		i_assert(p != NULL);
		value = p_strdup_printf(ctx->pool, "%s/"UNIQUE_KEY_SUFFIX"%s=%s",
					t_strdup_until(key, p), p + 1, value);
		break;
	case CONFIG_KEY_ERROR:
		value = p_strdup(ctx->pool, value);
		array_append(&ctx->errors, &value, 1);
		return;
	}
	array_append(&ctx->strings, &value, 1);
}

static int config_string_cmp(const char *const *p1, const char *const *p2)
{
	const char *s1 = *p1, *s2 = *p2;
	unsigned int i = 0;

	while (s1[i] == s2[i]) {
		if (s1[i] == '\0' || s1[i] == '=')
			return 0;
		i++;
	}

	if (s1[i] == '=')
		return -1;
	if (s2[i] == '=')
		return 1;

	return s1[i] - s2[i];
}

static struct prefix_stack prefix_stack_pop(ARRAY_TYPE(prefix_stack) *stack)
{
	const struct prefix_stack *s;
	struct prefix_stack sc;
	unsigned int count;

	s = array_get(stack, &count);
	i_assert(count > 0);
	if (count == 1) {
		sc.prefix_idx = -1U;
	} else {
		sc.prefix_idx = s[count-2].prefix_idx;
	}
	sc.str_pos = s[count-1].str_pos;
	array_delete(stack, count-1, 1);
	return sc;
}

static void prefix_stack_reset_str(ARRAY_TYPE(prefix_stack) *stack)
{
	struct prefix_stack *s;

	array_foreach_modifiable(stack, s)
		s->str_pos = -1U;
}

static struct config_dump_human_context *
config_dump_human_init(const char *module, enum config_dump_scope scope,
		       bool check_settings)
{
	struct config_dump_human_context *ctx;
	enum config_dump_flags flags;
	pool_t pool;

	pool = pool_alloconly_create("config human strings", 1024*32);
	ctx = p_new(pool, struct config_dump_human_context, 1);
	ctx->pool = pool;
	ctx->list_prefix = str_new(ctx->pool, 128);
	i_array_init(&ctx->strings, 256);
	i_array_init(&ctx->errors, 256);

	flags = CONFIG_DUMP_FLAG_HIDE_LIST_DEFAULTS |
		CONFIG_DUMP_FLAG_CALLBACK_ERRORS;
	if (check_settings)
		flags |= CONFIG_DUMP_FLAG_CHECK_SETTINGS;

	ctx->export_ctx = config_export_init(module, scope, flags,
					     config_request_get_strings, ctx);
	return ctx;
}

static void config_dump_human_deinit(struct config_dump_human_context *ctx)
{
	array_free(&ctx->strings);
	array_free(&ctx->errors);
	pool_unref(&ctx->pool);
}

static bool value_need_quote(const char *value)
{
	unsigned int len = strlen(value);

	if (len == 0)
		return FALSE;

	if (strchr(value, '#') != NULL)
		return TRUE;
	if (IS_WHITE(value[0]) || IS_WHITE(value[len-1]))
		return TRUE;
	return FALSE;
}

static int
config_dump_human_output(struct config_dump_human_context *ctx,
			 struct ostream *output, unsigned int indent,
			 const char *setting_name_filter)
{
	ARRAY_TYPE(const_string) prefixes_arr;
	ARRAY_TYPE(prefix_stack) prefix_stack;
	struct prefix_stack prefix;
	const char *const *strings, *const *args, *p, *str, *const *prefixes;
	const char *key, *key2, *value;
	unsigned int i, j, count, len, prefix_count, skip_len;
	unsigned int setting_name_filter_len, prefix_idx = -1U;
	bool unique_key;
	int ret = 0;

	setting_name_filter_len = setting_name_filter == NULL ? 0 :
		strlen(setting_name_filter);
	if (config_export_finish(&ctx->export_ctx) < 0)
		return -1;

	array_sort(&ctx->strings, config_string_cmp);
	strings = array_get(&ctx->strings, &count);

	/* strings are sorted so that all lists come first */
	p_array_init(&prefixes_arr, ctx->pool, 32);
	for (i = 0; i < count && strings[i][0] == LIST_KEY_PREFIX[0]; i++) T_BEGIN {
		p = strchr(strings[i], '=');
		i_assert(p != NULL);
		if (p[1] == '\0') {
			/* "strlist=" */
			str = p_strdup_printf(ctx->pool, "%s/",
					      t_strcut(strings[i]+1, '='));
			array_append(&prefixes_arr, &str, 1);
		} else {
			/* string is in format: "list=0 1 2" */
			for (args = t_strsplit(p + 1, " "); *args != NULL; args++) {
				str = p_strdup_printf(ctx->pool, "%s/%s/",
						      t_strcut(strings[i]+1, '='),
						      *args);
				array_append(&prefixes_arr, &str, 1);
			}
		}
	} T_END;
	prefixes = array_get(&prefixes_arr, &prefix_count);

	p_array_init(&prefix_stack, ctx->pool, 8);
	for (; i < count; i++) T_BEGIN {
		value = strchr(strings[i], '=');
		i_assert(value != NULL);

		key = t_strdup_until(strings[i], value++);
		unique_key = FALSE;

		p = strrchr(key, '/');
		if (p != NULL && p[1] == UNIQUE_KEY_SUFFIX[0]) {
			key = t_strconcat(t_strdup_until(key, p + 1),
					  p + 2, NULL);
			unique_key = TRUE;
		}
		if (setting_name_filter_len > 0) {
			/* see if this setting matches the name filter */
			if (!(strncmp(setting_name_filter, key,
				      setting_name_filter_len) == 0 &&
			      (key[setting_name_filter_len] == '/' ||
			       key[setting_name_filter_len] == '\0')))
				goto end;
		}
	again:
		j = 0;
		/* if there are open sections and this key isn't in it,
		   close the sections */
		while (prefix_idx != -1U) {
			len = strlen(prefixes[prefix_idx]);
			if (strncmp(prefixes[prefix_idx], key, len) != 0) {
				prefix = prefix_stack_pop(&prefix_stack);
				indent--;
				if (prefix.str_pos != -1U)
					str_truncate(ctx->list_prefix, prefix.str_pos);
				else {
					o_stream_send(output, indent_str, indent*2);
					o_stream_send_str(output, "}\n");
				}
				prefix_idx = prefix.prefix_idx;
			} else {
				/* keep the prefix */
				j = prefix_idx + 1;
				break;
			}
		}
		/* see if this key is in some section */
		for (; j < prefix_count; j++) {
			len = strlen(prefixes[j]);
			if (strncmp(prefixes[j], key, len) == 0) {
				key2 = key + (prefix_idx == -1U ? 0 :
					      strlen(prefixes[prefix_idx]));
				prefix.str_pos = !unique_key ? -1U :
					str_len(ctx->list_prefix);
				prefix_idx = j;
				prefix.prefix_idx = prefix_idx;
				array_append(&prefix_stack, &prefix, 1);

				str_append_n(ctx->list_prefix, indent_str, indent*2);
				p = strchr(key2, '/');
				if (p != NULL)
					str_append_n(ctx->list_prefix, key2, p - key2);
				else
					str_append(ctx->list_prefix, key2);
				if (unique_key && *value != '\0')
					str_printfa(ctx->list_prefix, " %s", value);
				str_append(ctx->list_prefix, " {\n");
				indent++;

				if (unique_key)
					goto end;
				else
					goto again;
			}
		}
		o_stream_send(output, str_data(ctx->list_prefix), str_len(ctx->list_prefix));
		str_truncate(ctx->list_prefix, 0);
		prefix_stack_reset_str(&prefix_stack);
		ctx->list_prefix_sent = TRUE;

		skip_len = prefix_idx == -1U ? 0 : strlen(prefixes[prefix_idx]);
		i_assert(skip_len == 0 ||
			 strncmp(prefixes[prefix_idx], strings[i], skip_len) == 0);
		o_stream_send(output, indent_str, indent*2);
		key = strings[i] + skip_len;
		if (unique_key) key++;
		value = strchr(key, '=');
		o_stream_send(output, key, value-key);
		o_stream_send_str(output, " = ");
		if (!value_need_quote(value+1))
			o_stream_send_str(output, value+1);
		else {
			o_stream_send(output, "\"", 1);
			o_stream_send_str(output, str_escape(value+1));
			o_stream_send(output, "\"", 1);
		}
		o_stream_send(output, "\n", 1);
	end: ;
	} T_END;

	while (prefix_idx != -1U) {
		prefix = prefix_stack_pop(&prefix_stack);
		if (prefix.str_pos != -1U)
			break;
		prefix_idx = prefix.prefix_idx;
		indent--;
		o_stream_send(output, indent_str, indent*2);
		o_stream_send_str(output, "}\n");
	}

	/* flush output before writing errors */
	o_stream_uncork(output);
	array_foreach(&ctx->errors, strings) {
		i_error("%s", *strings);
		ret = -1;
	}
	return ret;
}

static unsigned int
config_dump_filter_begin(string_t *str,
			 const struct config_filter *filter)
{
	unsigned int indent = 0;

	if (filter->local_bits > 0) {
		str_printfa(str, "local %s", filter->local_host);

		if (IPADDR_IS_V4(&filter->local_net)) {
			if (filter->local_bits != 32)
				str_printfa(str, "/%u", filter->local_bits);
		} else {
			if (filter->local_bits != 128)
				str_printfa(str, "/%u", filter->local_bits);
		}
		str_append(str, " {\n");
		indent++;
	}

	if (filter->local_name != NULL) {
		str_append_n(str, indent_str, indent*2);
		str_printfa(str, "local_name %s {\n", filter->local_name);
		indent++;
	}

	if (filter->remote_bits > 0) {
		str_append_n(str, indent_str, indent*2);
		str_printfa(str, "remote %s", filter->remote_host);

		if (IPADDR_IS_V4(&filter->remote_net)) {
			if (filter->remote_bits != 32)
				str_printfa(str, "/%u", filter->remote_bits);
		} else {
			if (filter->remote_bits != 128)
				str_printfa(str, "/%u", filter->remote_bits);
		}
		str_append(str, " {\n");
		indent++;
	}
	if (filter->service != NULL) {
		str_append_n(str, indent_str, indent*2);
		str_printfa(str, "protocol %s {\n", filter->service);
		indent++;
	}
	return indent;
}

static void
config_dump_filter_end(struct ostream *output, unsigned int indent)
{
	while (indent > 0) {
		indent--;
		o_stream_send(output, indent_str, indent*2);
		o_stream_send(output, "}\n", 2);
	}
}

static int
config_dump_human_sections(struct ostream *output,
			   const struct config_filter *filter,
			   const char *module)
{
	struct config_filter_parser *const *filters;
	static struct config_dump_human_context *ctx;
	unsigned int indent;
	int ret = 0;

	filters = config_filter_find_subset(config_filter, filter);

	/* first filter should be the global one */
	i_assert(filters[0] != NULL && filters[0]->filter.service == NULL);
	filters++;

	for (; *filters != NULL; filters++) {
		ctx = config_dump_human_init(module, CONFIG_DUMP_SCOPE_SET,
					     FALSE);
		indent = config_dump_filter_begin(ctx->list_prefix,
						  &(*filters)->filter);
		config_export_parsers(ctx->export_ctx, (*filters)->parsers);
		if (config_dump_human_output(ctx, output, indent, NULL) < 0)
			ret = -1;
		if (ctx->list_prefix_sent)
			config_dump_filter_end(output, indent);
		config_dump_human_deinit(ctx);
	}
	return ret;
}

static int
config_dump_human(const struct config_filter *filter, const char *module,
		  enum config_dump_scope scope, const char *setting_name_filter)
{
	static struct config_dump_human_context *ctx;
	struct ostream *output;
	int ret;

	output = o_stream_create_fd(STDOUT_FILENO, 0, FALSE);
	o_stream_cork(output);

	ctx = config_dump_human_init(module, scope, TRUE);
	config_export_by_filter(ctx->export_ctx, filter);
	ret = config_dump_human_output(ctx, output, 0, setting_name_filter);
	config_dump_human_deinit(ctx);

	if (ret == 0 && setting_name_filter == NULL)
		ret = config_dump_human_sections(output, filter, module);

	o_stream_uncork(output);
	o_stream_unref(&output);
	return ret;
}

static int
config_dump_one(const struct config_filter *filter, bool hide_key,
		enum config_dump_scope scope, const char *setting_name_filter)
{
	static struct config_dump_human_context *ctx;
	const char *const *str;
	unsigned int len;
	bool dump_section = FALSE;

	ctx = config_dump_human_init("", scope, TRUE);
	config_export_by_filter(ctx->export_ctx, filter);
	if (config_export_finish(&ctx->export_ctx) < 0)
		return -1;

	len = strlen(setting_name_filter);
	array_foreach(&ctx->strings, str) {
		if (strncmp(*str, setting_name_filter, len) != 0)
			continue;

		if ((*str)[len] == '=') {
			if (hide_key)
				printf("%s\n", *str + len+1);
			else {
				printf("%s = %s\n", setting_name_filter,
				       *str + len+1);
			}
			dump_section = FALSE;
			break;
		} else if ((*str)[len] == '/') {
			dump_section = TRUE;
		}
	}
	config_dump_human_deinit(ctx);

	if (dump_section)
		config_dump_human(filter, "", scope, setting_name_filter);
	return 0;
}

static void config_request_simple_stdout(const char *key, const char *value,
					 enum config_key_type type ATTR_UNUSED,
					 void *context)
{
	char **setting_name_filters = context;
	unsigned int i, filter_len;

	if (setting_name_filters == NULL) {
		printf("%s=%s\n", key, value);
		return;
	}

	for (i = 0; setting_name_filters[i] != NULL; i++) {
		filter_len = strlen(setting_name_filters[i]);
		if (strncmp(setting_name_filters[i], key, filter_len) == 0 &&
		    (key[filter_len] == '\0' || key[filter_len] == '/'))
			printf("%s=%s\n", key, value);
	}
}

static void config_request_putenv(const char *key, const char *value,
				  enum config_key_type type ATTR_UNUSED,
				  void *context ATTR_UNUSED)
{
	T_BEGIN {
		env_put(t_strconcat(t_str_ucase(key), "=", value, NULL));
	} T_END;
}

static const char *get_setting(const char *module, const char *name)
{
	struct config_module_parser *l;
	const struct setting_define *def;
	const char *const *value;
	const void *set;

	for (l = config_module_parsers; l->root != NULL; l++) {
		if (strcmp(l->root->module_name, module) != 0)
			continue;

		set = settings_parser_get(l->parser);
		for (def = l->root->defines; def->key != NULL; def++) {
			if (strcmp(def->key, name) == 0) {
				value = CONST_PTR_OFFSET(set, def->offset);
				return *value;
			}
		}
	}
	return "";
}

static void filter_parse_arg(struct config_filter *filter, const char *arg)
{
	const char *key, *value, *error;

	value = strchr(arg, '=');
	if (value != NULL)
		key = t_strdup_until(arg, value++);
	else {
		key = arg;
		value = "";
	}

	if (strcmp(key, "service") == 0)
		filter->service = value;
	else if (strcmp(key, "protocol") == 0)
		filter->service = value;
	else if (strcmp(key, "lname") == 0)
		filter->local_name = value;
	else if (strcmp(key, "local") == 0) {
		if (config_parse_net(value, &filter->local_net,
				     &filter->local_bits, &error) < 0)
			i_fatal("local filter: %s", error);
	} else if (strcmp(key, "remote") == 0) {
		if (config_parse_net(value, &filter->remote_net,
				     &filter->remote_bits, &error) < 0)
			i_fatal("remote filter: %s", error);
	} else {
		i_fatal("Unknown filter argument: %s", arg);
	}
}

static void check_wrong_config(const char *config_path)
{
	const char *base_dir, *symlink_path, *prev_path;

	base_dir = get_setting("master", "base_dir");
	symlink_path = t_strconcat(base_dir, "/"PACKAGE".conf", NULL);
	if (t_readlink(symlink_path, &prev_path) < 0)
		return;

	if (strcmp(prev_path, config_path) != 0) {
		i_warning("Dovecot was last started using %s, "
			  "but this config is %s", prev_path, config_path);
	}
}

static void failure_exit_callback(int *status)
{
	/* don't use EX_CONFIG, because it often causes MTAs to bounce
	   the mails back. */
	*status = EX_TEMPFAIL;
}

int main(int argc, char *argv[])
{
	enum config_dump_scope scope = CONFIG_DUMP_SCOPE_ALL;
	const char *orig_config_path, *config_path, *module = "";
	struct config_filter filter;
	const char *error;
	char **exec_args = NULL, **setting_name_filters = NULL;
	unsigned int i;
	int c, ret, ret2;
	bool config_path_specified, expand_vars = FALSE, hide_key = FALSE;
	bool parse_full_config = FALSE, simple_output = FALSE;

	if (getenv("USE_SYSEXITS") != NULL) {
		/* we're coming from (e.g.) LDA */
		i_set_failure_exit_callback(failure_exit_callback);
	}

	memset(&filter, 0, sizeof(filter));
	master_service = master_service_init("config",
					     MASTER_SERVICE_FLAG_STANDALONE,
					     &argc, &argv, "af:hm:nNpexS");
	orig_config_path = master_service_get_config_path(master_service);

	i_set_failure_prefix("doveconf: ");
	while ((c = master_getopt(master_service)) > 0) {
		if (c == 'e') {
			expand_vars = TRUE;
			break;
		}
		switch (c) {
		case 'a':
			break;
		case 'f':
			filter_parse_arg(&filter, optarg);
			break;
		case 'h':
			hide_key = TRUE;
			break;
		case 'm':
			module = optarg;
			break;
		case 'n':
			scope = CONFIG_DUMP_SCOPE_CHANGED;
			break;
		case 'N':
			scope = CONFIG_DUMP_SCOPE_SET;
			break;
		case 'p':
			parse_full_config = TRUE;
			break;
		case 'S':
			simple_output = TRUE;
			break;
		case 'x':
			expand_vars = TRUE;
			break;
		default:
			return FATAL_DEFAULT;
		}
	}
	config_path = master_service_get_config_path(master_service);
	/* use strcmp() instead of !=, because dovecot -n always gives us
	   -c parameter */
	config_path_specified = strcmp(config_path, orig_config_path) != 0;

	if (c == 'e') {
		if (argv[optind] == NULL)
			i_fatal("Missing command for -e");
		exec_args = &argv[optind];
	} else if (argv[optind] != NULL) {
		/* print only a single config setting */
		setting_name_filters = argv+optind;
	} else if (!simple_output) {
		/* print the config file path before parsing it, so in case
		   of errors it's still shown */
		printf("# "DOVECOT_VERSION_FULL": %s\n", config_path);
		fflush(stdout);
	}
	master_service_init_finish(master_service);
	config_parse_load_modules();

	if ((ret = config_parse_file(config_path, expand_vars,
				     parse_full_config ? "" : module,
				     &error)) == 0 &&
	    access(EXAMPLE_CONFIG_DIR, X_OK) == 0) {
		i_fatal("%s (copy example configs from "EXAMPLE_CONFIG_DIR"/)",
			error);
	}

	if ((ret == -1 && exec_args != NULL) || ret == 0 || ret == -2)
		i_fatal("%s", error);

	if (simple_output) {
		struct config_export_context *ctx;

		ctx = config_export_init(module, scope,
					 CONFIG_DUMP_FLAG_CHECK_SETTINGS,
					 config_request_simple_stdout,
					 setting_name_filters);
		config_export_by_filter(ctx, &filter);
		ret2 = config_export_finish(&ctx);
	} else if (setting_name_filters != NULL) {
		ret2 = 0;
		for (i = 0; setting_name_filters[i] != NULL; i++) {
			if (config_dump_one(&filter, hide_key, scope,
					    setting_name_filters[i]) < 0)
				ret2 = -1;
		}
	} else if (exec_args == NULL) {
		const char *info;

		info = sysinfo_get(get_setting("mail", "mail_location"));
		if (*info != '\0')
			printf("# %s\n", info);
		if (!config_path_specified)
			check_wrong_config(config_path);
		fflush(stdout);
		ret2 = config_dump_human(&filter, module, scope, NULL);
	} else {
		struct config_export_context *ctx;

		env_put("DOVECONF_ENV=1");
		ctx = config_export_init(module, CONFIG_DUMP_SCOPE_SET,
					 CONFIG_DUMP_FLAG_CHECK_SETTINGS,
					 config_request_putenv, NULL);
		config_export_by_filter(ctx, &filter);
		if (config_export_finish(&ctx) < 0)
			i_fatal("Invalid configuration");
		execvp(exec_args[0], exec_args);
		i_fatal("execvp(%s) failed: %m", exec_args[0]);
	}

	if (ret < 0) {
		/* delayed error */
		i_fatal("%s", error);
	}
	if (ret2 < 0)
		i_fatal("Errors in configuration");

	config_filter_deinit(&config_filter);
	module_dir_unload(&modules);
	master_service_deinit(&master_service);
        return 0;
}
