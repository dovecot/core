/* Copyright (C) 2005-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "env-util.h"
#include "ostream.h"
#include "settings-parser.h"
#include "master-service.h"
#include "all-settings.h"
#include "sysinfo-get.h"
#include "config-connection.h"
#include "config-parser.h"
#include "config-request.h"

#include <stdio.h>
#include <unistd.h>

struct config_request_get_string_ctx {
	pool_t pool;
	ARRAY_TYPE(const_string) strings;
};

static void
config_request_get_strings(const char *key, const char *value,
			   bool list, void *context)
{
	struct config_request_get_string_ctx *ctx = context;

	value = p_strdup_printf(ctx->pool, list ? "-%s=%s" : "%s=%s",
				key, value);
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

static unsigned int prefix_stack_pop(ARRAY_TYPE(uint) *stack)
{
	const unsigned int *indexes;
	unsigned int idx, count;

	indexes = array_get(stack, &count);
	idx = count <= 1 ? -1U : indexes[count-2];
	array_delete(stack, count-1, 1);
	return idx;
}

static void config_connection_request_human(struct ostream *output,
					    const struct config_filter *filter,
					    const char *module,
					    enum config_dump_scope scope)
{
	static const char *ident_str = "               ";
	ARRAY_TYPE(const_string) prefixes_arr;
	ARRAY_TYPE(uint) prefix_idx_stack;
	struct config_request_get_string_ctx ctx;
	const char *const *strings, *const *args, *p, *str, *const *prefixes;
	const char *key, *value;
	unsigned int i, j, count, len, prefix_count, skip_len;
	unsigned int indent = 0, prefix_idx = -1U;

	ctx.pool = pool_alloconly_create("config human strings", 10240);
	i_array_init(&ctx.strings, 256);
	if (config_request_handle(filter, module, scope, TRUE,
				  config_request_get_strings, &ctx) < 0)
		return;

	array_sort(&ctx.strings, config_string_cmp);
	strings = array_get(&ctx.strings, &count);

	p_array_init(&prefixes_arr, ctx.pool, 32);
	for (i = 0; i < count && strings[i][0] == '-'; i++) T_BEGIN {
		p = strchr(strings[i], '=');
		i_assert(p != NULL);
		for (args = t_strsplit(p + 1, " "); *args != NULL; args++) {
			str = p_strdup_printf(ctx.pool, "%s/%s/",
					      t_strcut(strings[i]+1, '='),
					      *args);
			array_append(&prefixes_arr, &str, 1);
		}
	} T_END;
	prefixes = array_get(&prefixes_arr, &prefix_count);

	p_array_init(&prefix_idx_stack, ctx.pool, 8);
	for (; i < count; i++) T_BEGIN {
		value = strchr(strings[i], '=');
		i_assert(value != NULL);
		key = t_strdup_until(strings[i], value);
		value++;

		j = 0;
		while (prefix_idx != -1U) {
			len = strlen(prefixes[prefix_idx]);
			if (strncmp(prefixes[prefix_idx], key, len) != 0) {
				prefix_idx = prefix_stack_pop(&prefix_idx_stack);
				indent--;
				o_stream_send(output, ident_str, indent*2);
				o_stream_send_str(output, "}\n");
			} else if (strchr(key + len, '/') == NULL) {
				/* keep the prefix */
				j = prefix_count;
				break;
			} else {
				/* subprefix */
				break;
			}
		}
		for (; j < prefix_count; j++) {
			len = strlen(prefixes[j]);
			if (strncmp(prefixes[j], key, len) == 0 &&
			    strchr(key + len, '/') == NULL) {
				key += prefix_idx == -1U ? 0 :
					strlen(prefixes[prefix_idx]);
				o_stream_send(output, ident_str, indent*2);
				o_stream_send_str(output, t_strcut(key, '/'));
				o_stream_send_str(output, " {\n");
				indent++;
				prefix_idx = j;
				array_append(&prefix_idx_stack, &prefix_idx, 1);
				break;
			}
		}
		skip_len = prefix_idx == -1U ? 0 : strlen(prefixes[prefix_idx]);
		i_assert(skip_len == 0 ||
			 strncmp(prefixes[prefix_idx], strings[i], skip_len) == 0);
		o_stream_send(output, ident_str, indent*2);
		key = strings[i] + skip_len;
		value = strchr(key, '=');
		o_stream_send(output, key, value-key);
		o_stream_send_str(output, " = ");
		o_stream_send_str(output, value+1);
		o_stream_send(output, "\n", 1);
	} T_END;

	while (prefix_idx != -1U) {
		prefix_idx = prefix_stack_pop(&prefix_idx_stack);
		indent--;
		o_stream_send(output, ident_str, indent*2);
		o_stream_send_str(output, "}\n");
	}

	array_free(&ctx.strings);
	pool_unref(&ctx.pool);
}

static void config_dump_human(const struct config_filter *filter,
			      const char *module,
			      enum config_dump_scope scope)
{
	struct ostream *output;

	output = o_stream_create_fd(STDOUT_FILENO, 0, FALSE);
	o_stream_cork(output);
	config_connection_request_human(output, filter, module, scope);
	o_stream_uncork(output);
	o_stream_unref(&output);
}

static void config_request_putenv(const char *key, const char *value,
				  bool list ATTR_UNUSED,
				  void *context ATTR_UNUSED)
{
	T_BEGIN {
		env_put(t_strconcat(t_str_ucase(key), "=", value, NULL));
	} T_END;
}

static const char *get_mail_location(void)
{
	struct config_module_parser *l;
	const struct setting_define *def;
	const char *const *value;
	const void *set;

	for (l = config_module_parsers; l->root != NULL; l++) {
		if (strcmp(l->root->module_name, "mail") != 0)
			continue;

		set = settings_parser_get(l->parser);
		for (def = l->root->defines; def->key != NULL; def++) {
			if (strcmp(def->key, "mail_location") == 0) {
				value = CONST_PTR_OFFSET(set, def->offset);
				return *value;
			}
		}
	}
	return "";
}

static void filter_parse_arg(struct config_filter *filter, const char *arg)
{
	if (strncmp(arg, "service=", 8) == 0)
		filter->service = arg + 8;
	else if (strncmp(arg, "protocol=", 9) == 0)
		filter->service = arg + 9;
	else if (strncmp(arg, "lip=", 4) == 0) {
		if (net_parse_range(arg + 4, &filter->local_net,
				    &filter->local_bits) < 0)
			i_fatal("lip: Invalid network mask");
	} else if (strncmp(arg, "rip=", 4) == 0) {
		if (net_parse_range(arg + 4, &filter->remote_net,
				    &filter->remote_bits) < 0)
			i_fatal("rip: Invalid network mask");
	} else {
		i_fatal("Unknown filter argument: %s", arg);
	}
}

int main(int argc, char *argv[])
{
	enum config_dump_scope scope = CONFIG_DUMP_SCOPE_ALL;
	const char *config_path, *module = "";
	struct config_filter filter;
	const char *error;
	char **exec_args = NULL;
	int c, ret;

	memset(&filter, 0, sizeof(filter));
	master_service = master_service_init("config",
					     MASTER_SERVICE_FLAG_STANDALONE,
					     &argc, &argv, "af:m:nNe");
	i_set_failure_prefix("doveconf: ");
	while ((c = master_getopt(master_service)) > 0) {
		if (c == 'e')
			break;
		switch (c) {
		case 'a':
			break;
		case 'f':
			filter_parse_arg(&filter, optarg);
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
		default:
			return FATAL_DEFAULT;
		}
	}
	config_path = master_service_get_config_path(master_service);

	if (argv[optind] != NULL) {
		if (c != 'e')
			i_fatal("Unknown argument: %s", argv[optind]);
		exec_args = &argv[optind];
	} else {
		/* print the config file path before parsing it, so in case
		   of errors it's still shown */
		printf("# "VERSION": %s\n", config_path);
		fflush(stdout);
	}
	master_service_init_finish(master_service);
	config_parse_load_modules();

	if ((ret = config_parse_file(config_path, FALSE, &error)) == 0 &&
	    access(EXAMPLE_CONFIG_DIR, X_OK) == 0) {
		i_fatal("%s (copy example configs from "EXAMPLE_CONFIG_DIR"/)",
			error);
	}
	if (ret <= 0)
		i_fatal("%s", error);

	if (exec_args == NULL) {
		const char *info;

		info = sysinfo_get(get_mail_location());
		if (*info != '\0')
			printf("# %s\n", info);
		fflush(stdout);
		config_dump_human(&filter, module, scope);
	} else {
		env_put("DOVECONF_ENV=1");
		if (config_request_handle(&filter, module,
					  CONFIG_DUMP_SCOPE_SET, TRUE,
					  config_request_putenv, NULL) < 0)
			i_fatal("Invalid configuration");
		execvp(exec_args[0], exec_args);
		i_fatal("execvp(%s) failed: %m", exec_args[0]);
	}
	config_filter_deinit(&config_filter);
	master_service_deinit(&master_service);
        return 0;
}
