/* Copyright (c) 2009-2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "str.h"
#include "strescape.h"
#include "net.h"
#include "doveadm.h"
#include "doveadm-cmd-parse.h"

#include <stdio.h>
#include <unistd.h>
#include <getopt.h>

ARRAY_DEFINE_TYPE(getopt_option_array, struct option);

static struct event_category event_category_doveadm = {
	.name = "doveadm",
};

struct doveadm_cmd_context*
doveadm_cmd_context_create(enum doveadm_client_type conn_type, bool forced_debug)
{
	pool_t pool = pool_alloconly_create("doveadm cmd", 256);
	struct event *event = event_create(NULL);
	event_set_append_log_prefix(event, "doveadm: ");
	event_set_forced_debug(event, forced_debug);
	event_add_category(event, &event_category_doveadm);

	struct doveadm_cmd_context *cctx = p_new(pool, struct doveadm_cmd_context, 1);
	cctx->pool = pool;
	cctx->event = event;
	cctx->conn_type = conn_type;
	return cctx;
}

void doveadm_cmd_context_unref(struct doveadm_cmd_context **_cctx)
{
	struct doveadm_cmd_context *cctx = *_cctx;
	*_cctx = NULL;

	event_unref(&cctx->event);
	pool_unref(&cctx->pool);
}

static const struct doveadm_cmd_param *
doveadm_cmd_param_get(const struct doveadm_cmd_context *cctx,
		      const char *name)
{
	i_assert(cctx != NULL);
	i_assert(cctx->argv != NULL);
	for(int i = 0; i < cctx->argc; i++) {
		if (strcmp(cctx->argv[i].name, name) == 0 &&
		    cctx->argv[i].value_set)
			return &cctx->argv[i];
	}
	return NULL;
}

bool doveadm_cmd_param_bool(const struct doveadm_cmd_context *cctx,
			    const char *name, bool *value_r)
{
	const struct doveadm_cmd_param *param;
	if ((param = doveadm_cmd_param_get(cctx, name)) == NULL)
		return FALSE;

	i_assert(param->type == CMD_PARAM_BOOL);
	*value_r = param->value.v_bool;
	return TRUE;
}

#define doveadm_cmd_param_int64_cast(type, check) \
bool doveadm_cmd_param_##type(const struct doveadm_cmd_context *cctx, \
			      const char *name, type##_t *value_r) \
{ \
	int64_t value; \
	bool ret = doveadm_cmd_param_int64(cctx, name, &value); \
	if (ret) { \
		i_assert(check); \
		*value_r = (type##_t) value; \
	} \
	return ret; \
}

doveadm_cmd_param_int64_cast(uint64, value >= 0)
doveadm_cmd_param_int64_cast(uint32, value >= 0 && value <= UINT32_MAX)
doveadm_cmd_param_int64_cast(int32, value >= INT32_MIN && value <= INT32_MAX)

bool doveadm_cmd_param_int64(const struct doveadm_cmd_context *cctx,
			     const char *name, int64_t *value_r)
{
	const struct doveadm_cmd_param *param;
	if ((param = doveadm_cmd_param_get(cctx, name)) == NULL)
		return FALSE;

	i_assert(param->type == CMD_PARAM_INT64);
	*value_r = param->value.v_int64;
	return TRUE;
}

bool doveadm_cmd_param_str(const struct doveadm_cmd_context *cctx,
			   const char *name, const char **value_r)
{
	const struct doveadm_cmd_param *param;
	if ((param = doveadm_cmd_param_get(cctx, name)) == NULL)
		return FALSE;

	i_assert(param->type == CMD_PARAM_STR);
	*value_r = param->value.v_string;
	return TRUE;
}

bool doveadm_cmd_param_ip(const struct doveadm_cmd_context *cctx,
			  const char *name, struct ip_addr *value_r)
{
	const struct doveadm_cmd_param *param;
	if ((param = doveadm_cmd_param_get(cctx, name)) == NULL)
		return FALSE;

	i_assert(param->type == CMD_PARAM_IP);
	memcpy(value_r, &param->value.v_ip, sizeof(struct ip_addr));
	return TRUE;
}

bool doveadm_cmd_param_array_get(const struct doveadm_cmd_context *cctx,
				 const char *name,
				 ARRAY_TYPE(const_string) *value_r)
{
	const struct doveadm_cmd_param *param;
	if ((param = doveadm_cmd_param_get(cctx, name)) == NULL)
		return FALSE;

	i_assert(param->type == CMD_PARAM_ARRAY);
	*value_r = param->value.v_array;
	return TRUE;
}


bool doveadm_cmd_param_array_append(const struct doveadm_cmd_context *cctx,
				    const char *name,
				    ARRAY_TYPE(const_string) *dest)
{
	ARRAY_TYPE(const_string) array;
	bool found = doveadm_cmd_param_array_get(cctx, name, &array);
	if (found) array_append_array(dest, &array);
	return found;
}

bool doveadm_cmd_param_array(const struct doveadm_cmd_context *cctx,
			     const char *name, const char *const **value_r)
{
	ARRAY_TYPE(const_string) array;
	bool found = doveadm_cmd_param_array_get(cctx, name, &array);
	if (found) {
		unsigned int count;
		*value_r = array_get(&array, &count);

		/* doveadm_cmd_params_null_terminate_arrays() should have been
		   called, which guarantees that we're NULL-terminated */
		i_assert((*value_r)[count] == NULL);
	}
	return found;
}

bool doveadm_cmd_param_istream(const struct doveadm_cmd_context *cctx,
			       const char *name, struct istream **value_r)
{
	const struct doveadm_cmd_param *param;
	if ((param = doveadm_cmd_param_get(cctx, name)) == NULL)
		return FALSE;

	i_assert(param->type == CMD_PARAM_ISTREAM);
	*value_r = param->value.v_istream;
	return TRUE;
}

void doveadm_cmd_params_clean(ARRAY_TYPE(doveadm_cmd_param_arr_t) *pargv)
{
	struct doveadm_cmd_param *param;

	array_foreach_modifiable(pargv, param) {
		if (param->type == CMD_PARAM_ISTREAM &&
		    param->value.v_istream != NULL)
			i_stream_destroy(&param->value.v_istream);
	}
	array_clear(pargv);
}

void doveadm_cmd_params_null_terminate_arrays(
	ARRAY_TYPE(doveadm_cmd_param_arr_t) *pargv)
{
	struct doveadm_cmd_param *param;

	array_foreach_modifiable(pargv, param) {
		if (param->type == CMD_PARAM_ARRAY &&
		    array_is_created(&param->value.v_array)) {
			array_append_zero(&param->value.v_array);
			array_pop_back(&param->value.v_array);
		}
	}
}

static void
doveadm_build_options(const struct doveadm_cmd_param par[],
		      string_t *shortopts,
		      ARRAY_TYPE(getopt_option_array) *longopts)
{
	for (size_t i = 0; par[i].name != NULL; i++) {
		struct option longopt;

		i_zero(&longopt);
		longopt.name = par[i].name;
		if (par[i].short_opt != '\0') {
			longopt.val = par[i].short_opt;
			str_append_c(shortopts, par[i].short_opt);
			if (par[i].type != CMD_PARAM_BOOL)
				str_append_c(shortopts, ':');
		}
		if (par[i].type != CMD_PARAM_BOOL)
			longopt.has_arg = 1;
		array_push_back(longopts, &longopt);
	}
	array_append_zero(longopts);
}

static int
doveadm_fill_param(struct doveadm_cmd_param *param,
		   const char *value, pool_t pool,
		   const char **error_r)
{
	param->value_set = TRUE;
	switch (param->type) {
	case CMD_PARAM_BOOL:
		param->value.v_bool = TRUE;
		break;
	case CMD_PARAM_INT64:
		if (str_to_int64(value, &param->value.v_int64) != 0) {
			param->value_set = FALSE;
			*error_r = t_strdup_printf(
					"Invalid number: %s", value);
			return -1;
		}
		if ((param->flags & CMD_PARAM_FLAG_UNSIGNED) != 0 &&
		    param->value.v_int64 < 0) {
		    	param->value_set = FALSE;
			*error_r = t_strdup_printf(
					"Cannot be negative: %s", value);
		    	param->value_set = FALSE;
			return -1;
		}
		break;
	case CMD_PARAM_IP:
		if (net_addr2ip(value, &param->value.v_ip) != 0) {
			param->value_set = FALSE;
			*error_r = t_strdup_printf(
					"Invalid IP address: %s", value);
			return -1;
		}
		break;
	case CMD_PARAM_STR:
		param->value.v_string = p_strdup(pool, value);
		break;
	case CMD_PARAM_ARRAY:
		if (!array_is_created(&param->value.v_array))
			p_array_init(&param->value.v_array, pool, 8);
		const char *val = p_strdup(pool, value);
		array_push_back(&param->value.v_array, &val);
		break;
	case CMD_PARAM_ISTREAM: {
		struct istream *is;
		if (strcmp(value,"-") == 0)
			is = i_stream_create_fd(STDIN_FILENO, IO_BLOCK_SIZE);
		else
			is = i_stream_create_file(value, IO_BLOCK_SIZE);
		param->value.v_istream = is;
		if (is->stream_errno < 0) {
			param->value_set = FALSE;
			*error_r = t_strdup_printf("read(%s) failed: %s",
				i_stream_get_name(is), i_stream_get_error(is));
			return -1;
		}
		break;
	}
	default:
		i_unreached();
	}
	return 0;
}

static int
doveadm_cmd_process_options(int argc, const char *const argv[],
			    struct doveadm_cmd_context *cctx, pool_t pool,
			    ARRAY_TYPE(doveadm_cmd_param_arr_t) *pargv)
{
	struct doveadm_cmd_param *param;
	ARRAY_TYPE(getopt_option_array) opts;
	string_t *optbuf = str_new(pool, 64);

	p_array_init(&opts, pool, 4);

	// build parameters
	if ((cctx->cmd->flags & CMD_FLAG_NO_UNORDERED_OPTIONS) != 0)
		str_append_c(optbuf, '+');
	doveadm_build_options(cctx->cmd->parameters, optbuf, &opts);

	unsigned int pargc;
	for (pargc = 0; cctx->cmd->parameters[pargc].name != NULL; pargc++) {
		param = array_append_space(pargv);
		memcpy(param, &cctx->cmd->parameters[pargc],
		       sizeof(struct doveadm_cmd_param));
		param->value_set = FALSE;
	}
	i_assert(pargc == array_count(&opts)-1); /* opts is NULL-terminated */

	if ((cctx->cmd->flags & CMD_FLAG_NO_OPTIONS) != 0) {
		/* process -parameters as if they were regular parameters */
		optind = 1;
		return 0;
	}

	int c, li;
	while ((c = getopt_long(argc, (char *const *)argv, str_c(optbuf),
				array_front(&opts), &li)) > -1) {
		switch (c) {
		case 0:
			for (unsigned int i = 0; i < array_count(pargv); i++) {
				const char *error;
				const struct option *opt = array_idx(&opts, li);
				param = array_idx_modifiable(pargv, i);
				if (opt->name == param->name &&
				    doveadm_fill_param(
					param, optarg, pool, &error) < 0) {
					e_error(cctx->event,
						"Invalid parameter: %s", error);
					doveadm_cmd_params_clean(pargv);
					return -1;
				}
			}
			break;
		case '?':
			e_error(cctx->event,
				"Unexpected or incomplete option: -%c", optopt);
			doveadm_cmd_params_clean(pargv);
			return -1;
		case ':':
			e_error(cctx->event,
				"Option not followed by argument: -%c", optopt);
			doveadm_cmd_params_clean(pargv);
			return -1;
		default:
			// hunt the option
			for (unsigned int i = 0; i < pargc; i++) {
				const char *error;
				const struct option *longopt =
					array_idx(&opts, i);
				if (longopt->val == c &&
				    doveadm_fill_param(
					array_idx_modifiable(pargv, i),
					optarg, pool, &error) < 0) {
					e_error(cctx->event,
						"Invalid parameter: %s", error);
					doveadm_cmd_params_clean(pargv);
					return -1;
				}
			}
		}
	}
	return 0;
}

int doveadm_cmdline_run(int argc, const char *const argv[],
			struct doveadm_cmd_context *cctx)
{
	ARRAY_TYPE(doveadm_cmd_param_arr_t) pargv;
	unsigned int pargc;
	pool_t pool = pool_datastack_create();

	i_getopt_reset();
	p_array_init(&pargv, pool, 20);
	if (doveadm_cmd_process_options(argc, argv, cctx, pool, &pargv) < 0)
		return -1;

	unsigned int ptr_count;
	struct doveadm_cmd_param *ptr = array_get_modifiable(&pargv, &ptr_count);
	struct doveadm_cmd_param *ptr_end = ptr + ptr_count;
	struct doveadm_cmd_param *ptr_last_non_kv = ptr;

	/* process positional arguments */
	for (; optind < argc; optind++) {
		bool found = FALSE;
		bool is_keyvalue = FALSE;
		for (; ptr < ptr_end; ptr++) {
			if ((ptr->flags & CMD_PARAM_FLAG_POSITIONAL) == 0)
				continue;
			if ((ptr->flags & CMD_PARAM_FLAG_KEY_VALUE) == 0)
				ptr_last_non_kv = ptr;
			if (ptr->value_set && ptr->type != CMD_PARAM_ARRAY)
				continue;
			if ((ptr->flags & CMD_PARAM_FLAG_KEY_VALUE) != 0) {
				if (optind + 1 >= argc)
					continue;
				if (strcmp(ptr->key, argv[optind]) != 0)
					continue;
				optind++;
				is_keyvalue = TRUE;
			}

			const char *error;
			if (doveadm_fill_param(ptr, argv[optind], pool, &error) < 0) {
				e_error(cctx->event, "Invalid parameter: %s",
					t_strarray_join(argv + optind, " "));
				doveadm_cmd_params_clean(&pargv);
				return -1;
			}
			found = TRUE;
			break;
		}
		if (!found) {
			e_error(cctx->event, "Extraneous arguments found: %s",
				t_strarray_join(argv + optind, " "));
			doveadm_cmd_params_clean(&pargv);
			return -1;
		}
		if (is_keyvalue)
			ptr = ptr_last_non_kv;
	}

	doveadm_cmd_params_null_terminate_arrays(&pargv);
	cctx->argv = array_get_modifiable(&pargv, &pargc);
	cctx->argc = pargc;

	if (cctx->cmd->name != NULL) {
		const char * prefix = t_strdup_printf("cmd %s: ", cctx->cmd->name);
		event_set_append_log_prefix(cctx->event, prefix);
		cctx->cmd->cmd(cctx);
		event_drop_parent_log_prefixes(cctx->event, 1);
	} else
		cctx->cmd->cmd(cctx);

	doveadm_cmd_params_clean(&pargv);
	return 0;
}

static const char*
doveadm_cmd_param_tostring(const struct doveadm_cmd_param *argv)
{
	if (!argv->value_set)
		return "";
	switch(argv->type) {
	case CMD_PARAM_ISTREAM:
		return "stream";
	case CMD_PARAM_BOOL:
		return argv->value.v_bool ? "TRUE" : "FALSE";
	case CMD_PARAM_IP:
		return net_ip2addr(&argv->value.v_ip);
	case CMD_PARAM_INT64:
		return t_strdup_printf("%"PRId64, argv->value.v_int64);
	case CMD_PARAM_STR: {
		const char *item = argv->value.v_string;
		size_t item_len = strlen(item);
		string_t *value = t_str_new(item_len + 2);
		str_append_c(value, '"');
		str_append_escaped(value, item, item_len);
		str_append_c(value, '"');
		return str_c(value);
	}
	case CMD_PARAM_ARRAY: {
		string_t *value = t_str_new(64);
		const char *const *item;
		array_foreach(&argv->value.v_array, item) {
			if (str_len(value) > 0) str_append(value, ", ");
			str_append_c(value, '"');
			str_append_escaped(value, *item, strlen(*item));
			str_append_c(value, '"');
		}
		return str_c(value);
	}
	default:
		return "";
	}
}

void doveadm_cmd_params_dump(const struct doveadm_cmd_context *cctx)
{
	e_debug(cctx->event, "%s()", __func__);
	i_assert(cctx != NULL);
	i_assert(cctx->argv != NULL);
	const struct doveadm_cmd_param *argv = cctx->argv;
	for (int index = 0; index < cctx->argc; index++, argv++) T_BEGIN {
		const char *value = doveadm_cmd_param_tostring(argv);
		e_debug(cctx->event, "    %c%c%c%c %02x/%02x -%c %s: %s",
			*value != '\0' ? 'S': '-',
			argv->type == CMD_PARAM_ARRAY ? 'A': '-',
			(argv->flags & CMD_PARAM_FLAG_POSITIONAL) != 0 ? 'P': '-',
			(argv->flags & CMD_PARAM_FLAG_KEY_VALUE) != 0 ? 'N': '-',
			(int)argv->type, (int)argv->flags,
			argv->short_opt != '\0' ? argv->short_opt : '-',
			argv->name, value);
	} T_END;
}

void doveadm_cmd_args_dump(const char *const *items)
{
	i_debug("%s()", __func__);
	for (; *items != NULL; items++)
		i_debug("    %s", *items);
}
