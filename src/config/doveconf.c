/* Copyright (C) 2005-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "env-util.h"
#include "master-service.h"
#include "ostream.h"
#include "config-connection.h"
#include "config-parser.h"
#include "config-request.h"

#include <stdlib.h>
#include <unistd.h>

struct config_request_get_string_ctx {
	pool_t pool;
	ARRAY_TYPE(const_string) strings;
};

static struct master_service *service;

static void
config_request_get_strings(const char *key, const char *value,
			   bool list, void *context)
{
	struct config_request_get_string_ctx *ctx = context;

	value = p_strdup_printf(ctx->pool, list ? "-%s=%s" : "%s=%s",
				key, value);
	array_append(&ctx->strings, &value, 1);
}

static int config_string_cmp(const void *p1, const void *p2)
{
	const char *s1 = *(const char *const *)p1;
	const char *s2 = *(const char *const *)p2;
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
					    const char *service,
					    enum config_dump_flags flags)
{
	static const char *ident_str = "               ";
	ARRAY_TYPE(const_string) prefixes_arr;
	ARRAY_TYPE(uint) prefix_idx_stack;
	struct config_request_get_string_ctx ctx;
	const char **strings, *const *args, *p, *str, *const *prefixes;
	const char *key, *value;
	unsigned int i, j, count, len, prefix_count, skip_len;
	unsigned int indent = 0, prefix_idx = -1U;

	ctx.pool = pool_alloconly_create("config human strings", 10240);
	i_array_init(&ctx.strings, 256);
	config_request_handle(service, flags, config_request_get_strings, &ctx);

	strings = array_get_modifiable(&ctx.strings, &count);
	qsort(strings, count, sizeof(*strings), config_string_cmp);

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
		i_assert(strncmp(prefixes[prefix_idx], strings[i], skip_len) == 0);
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

static void config_dump_human(const char *service, enum config_dump_flags flags)
{
	struct ostream *output;

	output = o_stream_create_fd(STDOUT_FILENO, 0, FALSE);
	o_stream_cork(output);
	config_connection_request_human(output, service, flags);
	o_stream_uncork(output);
}

static void config_request_putenv(const char *key, const char *value,
				  bool list ATTR_UNUSED,
				  void *context ATTR_UNUSED)
{
	T_BEGIN {
		env_put(t_strconcat(t_str_ucase(key), "=", value, NULL));
	} T_END;
}

int main(int argc, char *argv[])
{
	enum config_dump_flags flags = CONFIG_DUMP_FLAG_DEFAULTS;
	const char *getopt_str, *service_name = "";
	char **exec_args = NULL;
	int c;

	service = master_service_init("config", 0, argc, argv);

	getopt_str = t_strconcat("anp:e", master_service_getopt_string(), NULL);
	while ((c = getopt(argc, argv, getopt_str)) > 0) {
		if (c == 'e')
			break;
		switch (c) {
		case 'a':
			break;
		case 'n':
			flags &= ~CONFIG_DUMP_FLAG_DEFAULTS;
			break;
		case 'p':
			service_name = optarg;
			break;
		default:
			if (!master_service_parse_option(service, c, optarg))
				exit(FATAL_DEFAULT);
		}
	}
	if (argv[optind] != NULL)
		exec_args = &argv[optind];

	master_service_init_log(service, "doveconf: ", 0);
	master_service_init_finish(service);

	config_parse_file(master_service_get_config_path(service),
			  service_name);

	if (exec_args == NULL)
		config_dump_human(service_name, flags);
	else {
		env_put("DOVECONF_ENV=1");
		config_request_handle(service_name, 0,
				      config_request_putenv, NULL);
		execvp(exec_args[0], exec_args);
		i_fatal("execvp(%s) failed: %m", exec_args[0]);
	}
	master_service_deinit(&service);
        return 0;
}
