/* Copyright (c) 2009-2r016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "str.h"
#include "net.h"
#include "doveadm.h"
#include "doveadm-cmd.h"

#include <stdio.h>
#include <unistd.h>
#include <getopt.h>

static struct doveadm_cmd *doveadm_commands[] = {
	&doveadm_cmd_mailbox_mutf7,
	&doveadm_cmd_sis_deduplicate,
	&doveadm_cmd_sis_find,
};

static struct doveadm_cmd_ver2 *doveadm_commands_ver2[] = {
	&doveadm_cmd_service_stop_ver2,
	&doveadm_cmd_service_status_ver2,
	&doveadm_cmd_process_status_ver2,
	&doveadm_cmd_stop_ver2,
	&doveadm_cmd_reload_ver2,
	&doveadm_cmd_stats_dump_ver2,
	&doveadm_cmd_oldstats_dump_ver2,
	&doveadm_cmd_oldstats_reset_ver2,
	&doveadm_cmd_penalty_ver2,
	&doveadm_cmd_kick_ver2,
	&doveadm_cmd_who_ver2
};

static const struct exit_code_str {
	int code;
	const char *str;
} exit_code_strings[] = {
	{ DOVEADM_EX_UNKNOWN, "UNKNOWN" },
	{ EX_TEMPFAIL, "TEMPFAIL" },
	{ EX_USAGE, "USAGE" },
	{ EX_NOUSER, "NOUSER" },
	{ EX_NOPERM, "NOPERM" },
	{ EX_PROTOCOL, "PROTOCOL" },
	{ EX_DATAERR, "DATAERR" },
	{ DOVEADM_EX_NOTFOUND, "NOTFOUND" }
};

ARRAY_TYPE(doveadm_cmd) doveadm_cmds;
ARRAY_TYPE(doveadm_cmd_ver2) doveadm_cmds_ver2;
ARRAY_DEFINE_TYPE(getopt_option_array, struct option);

const char *doveadm_exit_code_to_str(int code)
{
	for(size_t i = 0; i < N_ELEMENTS(exit_code_strings); i++) {
		const struct exit_code_str *ptr = &exit_code_strings[i];
		if (ptr->code == code)
			return ptr->str;
	}
	return "UNKNOWN";
}

int doveadm_str_to_exit_code(const char *reason)
{
	for(size_t i = 0; i < N_ELEMENTS(exit_code_strings); i++) {
		const struct exit_code_str *ptr = &exit_code_strings[i];
		if (strcmp(ptr->str, reason) == 0)
			return ptr->code;
	}
	return DOVEADM_EX_UNKNOWN;
}

void doveadm_register_cmd(const struct doveadm_cmd *cmd)
{
	array_push_back(&doveadm_cmds, cmd);
}

void doveadm_cmd_register_ver2(struct doveadm_cmd_ver2 *cmd)
{
	if (cmd->cmd == NULL) {
		if (cmd->mail_cmd != NULL)
			cmd->cmd = doveadm_cmd_ver2_to_mail_cmd_wrapper;
		else if (cmd->old_cmd != NULL)
			cmd->cmd = doveadm_cmd_ver2_to_cmd_wrapper;
		else i_unreached();
	}
	array_push_back(&doveadm_cmds_ver2, cmd);
}

const struct doveadm_cmd_ver2 *doveadm_cmd_find_ver2(const char *cmd_name)
{
	const struct doveadm_cmd_ver2 *cmd;

	array_foreach(&doveadm_cmds_ver2, cmd) {
		if (strcmp(cmd_name, cmd->name)==0)
			return cmd;
	}
	return NULL;
}

const struct doveadm_cmd_ver2 *
doveadm_cmd_find_with_args_ver2(const char *cmd_name, int *argc,
				const char *const *argv[])
{
	int i, k;
	const struct doveadm_cmd_ver2 *cmd;
	const char *cptr;

	for(i=0;i<*argc;i++) {
		if (strcmp((*argv)[i],cmd_name)==0) break;
	}

	i_assert(i != *argc);

	array_foreach(&doveadm_cmds_ver2, cmd) {
		cptr = cmd->name;
		/* cannot reuse i here because this needs be
		   done more than once */
		for (k=0; *cptr != '\0' && i+k < *argc; k++) {
			size_t alen = strlen((*argv)[i+k]);
			/* make sure we don't overstep */
			if (strlen(cptr) < alen) break;
			/* did not match */
			if (strncmp(cptr, (*argv)[i+k], alen) != 0) break;
			/* do not accept abbreviations */
			if (cptr[alen] != ' ' && cptr[alen] != '\0') break;
			cptr += alen;
			if (*cptr != '\0') cptr++; /* consume space */
		}
		/* name was fully consumed */
		if (*cptr == '\0') {
			if (k > 1) {
				*argc -= k-1;
				*argv += k-1;
			}
			return cmd;
		}
	}

	return NULL;
}

static bool
doveadm_cmd_find_multi_word(const char *cmdname, int *_argc,
			    const char *const *_argv[])
{
	int argc = *_argc;
	const char *const *argv = *_argv;
	size_t len;

	if (argc < 2)
		return FALSE;

	len = strlen(argv[1]);
	if (!str_begins(cmdname, argv[1]))
		return FALSE;

	argc--; argv++;
	if (cmdname[len] == ' ') {
		/* more args */
		if (!doveadm_cmd_find_multi_word(cmdname + len + 1,
						 &argc, &argv))
			return FALSE;
	} else {
		if (cmdname[len] != '\0')
			return FALSE;
	}

	*_argc = argc;
	*_argv = argv;
	return TRUE;
}

const struct doveadm_cmd *
doveadm_cmd_find_with_args(const char *cmd_name, int *argc,
			   const char *const *argv[])
{
	const struct doveadm_cmd *cmd;
	size_t cmd_name_len;

	i_assert(*argc > 0);

	cmd_name_len = strlen(cmd_name);
	array_foreach(&doveadm_cmds, cmd) {
		if (strcmp(cmd->name, cmd_name) == 0)
			return cmd;

		/* see if it matches a multi-word command */
		if (strncmp(cmd->name, cmd_name, cmd_name_len) == 0 &&
		    cmd->name[cmd_name_len] == ' ') {
			const char *subcmd_name = cmd->name + cmd_name_len + 1;

			if (doveadm_cmd_find_multi_word(subcmd_name,
							argc, argv))
				return cmd;
		}
	}
	return NULL;
}

void doveadm_cmds_init(void)
{
	unsigned int i;

	i_array_init(&doveadm_cmds, 32);
	i_array_init(&doveadm_cmds_ver2, 2);

	for (i = 0; i < N_ELEMENTS(doveadm_commands); i++)
		doveadm_register_cmd(doveadm_commands[i]);

	for (i = 0; i < N_ELEMENTS(doveadm_commands_ver2); i++)
		doveadm_cmd_register_ver2(doveadm_commands_ver2[i]);

	doveadm_register_director_commands();
	doveadm_register_instance_commands();
	doveadm_register_proxy_commands();
	doveadm_register_log_commands();
	doveadm_register_replicator_commands();
	doveadm_register_dict_commands();
	doveadm_register_fs_commands();
}

void doveadm_cmds_deinit(void)
{
	array_free(&doveadm_cmds);
	array_free(&doveadm_cmds_ver2);
}

static const struct doveadm_cmd_param*
doveadm_cmd_param_get(const struct doveadm_cmd_context *cctx,
		      const char *name)
{
	i_assert(cctx != NULL);
	i_assert(cctx->argv != NULL);
	for(int i = 0; i < cctx->argc; i++) {
		if (strcmp(cctx->argv[i].name, name) == 0 && cctx->argv[i].value_set)
			return &cctx->argv[i];
	}
	return NULL;
}

bool doveadm_cmd_param_bool(const struct doveadm_cmd_context *cctx,
			    const char *name, bool *value_r)
{
	const struct doveadm_cmd_param *param;
	if ((param = doveadm_cmd_param_get(cctx, name))==NULL) return FALSE;

	if (param->type == CMD_PARAM_BOOL) {
		*value_r = param->value.v_bool;
		return TRUE;
	}
	return FALSE;
}

bool doveadm_cmd_param_int64(const struct doveadm_cmd_context *cctx,
			     const char *name, int64_t *value_r)
{
	const struct doveadm_cmd_param *param;
	if ((param = doveadm_cmd_param_get(cctx, name))==NULL) return FALSE;

	if (param->type == CMD_PARAM_INT64) {
		*value_r = param->value.v_int64;
		return TRUE;
	}
	return FALSE;
}

bool doveadm_cmd_param_str(const struct doveadm_cmd_context *cctx,
			   const char *name, const char **value_r)
{
	const struct doveadm_cmd_param *param;
	if ((param = doveadm_cmd_param_get(cctx, name))==NULL) return FALSE;

	if (param->type == CMD_PARAM_STR) {
		*value_r = param->value.v_string;
		return TRUE;
	}
	return FALSE;
}

bool doveadm_cmd_param_ip(const struct doveadm_cmd_context *cctx,
			  const char *name, struct ip_addr *value_r)
{
	const struct doveadm_cmd_param *param;
	if ((param = doveadm_cmd_param_get(cctx, name))==NULL) return FALSE;

	if (param->type == CMD_PARAM_IP) {
		memcpy(value_r, &param->value.v_ip, sizeof(struct ip_addr));
		return TRUE;
	}
	return FALSE;
}

bool doveadm_cmd_param_array(const struct doveadm_cmd_context *cctx,
			     const char *name, const char *const **value_r)
{
	const struct doveadm_cmd_param *param;
	unsigned int count;

	if ((param = doveadm_cmd_param_get(cctx, name))==NULL) return FALSE;
	if (param->type == CMD_PARAM_ARRAY) {
		*value_r = array_get(&param->value.v_array, &count);
		/* doveadm_cmd_params_null_terminate_arrays() should have been
		   called, which guarantees that we're NULL-terminated */
		i_assert((*value_r)[count] == NULL);
		return TRUE;
	}
	return FALSE;
}

bool doveadm_cmd_param_istream(const struct doveadm_cmd_context *cctx,
			       const char *name, struct istream **value_r)
{
	const struct doveadm_cmd_param *param;
	if ((param = doveadm_cmd_param_get(cctx, name))==NULL) return FALSE;

	if (param->type == CMD_PARAM_ISTREAM) {
		*value_r = param->value.v_istream;
		return TRUE;
	}
	return FALSE;
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

void doveadm_cmd_params_null_terminate_arrays(ARRAY_TYPE(doveadm_cmd_param_arr_t) *pargv)
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
doveadm_cmd_params_to_argv(const char *name, int pargc, const struct doveadm_cmd_param* params,
	ARRAY_TYPE(const_string) *argv)
{
	bool array_add_opt;
	int i;
	const char * const * cptr;
	i_assert(array_count(argv) == 0);
	array_push_back(argv, &name);

	ARRAY_TYPE(const_string) pargv;
	t_array_init(&pargv, 8);

	for(i=0;i<pargc;i++) {
		const char *optarg = NULL;
		ARRAY_TYPE(const_string) *target = argv;
		if ((params[i].flags & CMD_PARAM_FLAG_POSITIONAL) != 0)
			target = &pargv;
		/* istreams are special */
		i_assert(params[i].type != CMD_PARAM_ISTREAM);
		if (params[i].value_set) {
			array_add_opt = FALSE;
			if (params[i].short_opt != '\0') {
				if (params[i].type == CMD_PARAM_ARRAY) {
					array_add_opt = TRUE;
				} else {
					optarg = t_strdup_printf("-%c", params[i].short_opt);
					array_push_back(argv, &optarg);
				}
			}
			/* CMD_PARAM_BOOL is implicitly handled above */
			if (params[i].type == CMD_PARAM_STR) {
				array_push_back(target,
						&params[i].value.v_string);
			} else if (params[i].type == CMD_PARAM_INT64) {
				const char *tmp = t_strdup_printf("%lld",
					(long long)params[i].value.v_int64);
				array_push_back(target, &tmp);
			} else if (params[i].type == CMD_PARAM_IP) {
				const char *tmp = net_ip2addr(&params[i].value.v_ip);
				array_push_back(target, &tmp);
			} else if (params[i].type == CMD_PARAM_ARRAY) {
				array_foreach(&params[i].value.v_array, cptr) {
					if (array_add_opt)
						array_push_back(argv, &optarg);
					array_push_back(target, cptr);
				}
			}
		}
	}

	if (array_count(&pargv) > 0) {
		const char *dashdash = "--";
		array_push_back(argv, &dashdash);
		array_append_array(argv, &pargv);
	}
	array_append_zero(argv);
}

void
doveadm_cmd_ver2_to_cmd_wrapper(struct doveadm_cmd_context *cctx)
{
	unsigned int pargc;
	const char **pargv;

	i_assert(cctx->cmd->old_cmd != NULL);

	ARRAY_TYPE(const_string) nargv;
	t_array_init(&nargv, 8);
	doveadm_cmd_params_to_argv(cctx->cmd->name, cctx->argc, cctx->argv, &nargv);
	pargv = array_get_modifiable(&nargv, &pargc);
	i_getopt_reset();
	cctx->cmd->old_cmd(pargc-1, (char**)pargv);
}

static void
doveadm_build_options(const struct doveadm_cmd_param par[],
		string_t *shortopts,
		ARRAY_TYPE(getopt_option_array) *longopts)
{
	for(size_t i=0; par[i].name != NULL; i++) {
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

static void doveadm_fill_param(struct doveadm_cmd_param *param,
	const char *value, pool_t pool)
{
	param->value_set = TRUE;
	switch(param->type) {
	case CMD_PARAM_BOOL:
		param->value.v_bool = TRUE; break;
	case CMD_PARAM_INT64:
		if (str_to_int64(value, &param->value.v_int64) != 0) {
			param->value_set = FALSE;
		}
		break;
	case CMD_PARAM_IP:
		if (net_addr2ip(value, &param->value.v_ip) != 0) {
			param->value_set = FALSE;
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
		if (strcmp(value,"-") == 0) {
			is = i_stream_create_fd(STDIN_FILENO, IO_BLOCK_SIZE);
		} else {
			is = i_stream_create_file(value, IO_BLOCK_SIZE);
		}
		param->value.v_istream = is;
	}
	}
}

bool doveadm_cmd_try_run_ver2(const char *cmd_name,
			      int argc, const char *const argv[],
			      struct doveadm_cmd_context *cctx)
{
	const struct doveadm_cmd_ver2 *cmd;

	cmd = doveadm_cmd_find_with_args_ver2(cmd_name, &argc, &argv);
	if (cmd == NULL)
		return FALSE;

	cctx->cmd = cmd;
	if (doveadm_cmd_run_ver2(argc, argv, cctx) < 0)
		doveadm_exit_code = EX_USAGE;
	return TRUE;
}

int doveadm_cmd_run_ver2(int argc, const char *const argv[],
			 struct doveadm_cmd_context *cctx)
{
	struct doveadm_cmd_param *param;
	ARRAY_TYPE(doveadm_cmd_param_arr_t) pargv;
	ARRAY_TYPE(getopt_option_array) opts;
	unsigned int pargc;
	int c,li;
	pool_t pool = pool_datastack_create();
	string_t *optbuf = str_new(pool, 64);

	p_array_init(&opts, pool, 4);

	// build parameters
	doveadm_build_options(cctx->cmd->parameters, optbuf, &opts);

	p_array_init(&pargv, pool, 20);

	for(pargc=0;cctx->cmd->parameters[pargc].name != NULL;pargc++) {
		param = array_append_space(&pargv);
		memcpy(param, &cctx->cmd->parameters[pargc], sizeof(struct doveadm_cmd_param));
		param->value_set = FALSE;
	}
	i_assert(pargc == array_count(&opts)-1); /* opts is NULL-terminated */

	while((c = getopt_long(argc, (char*const*)argv, str_c(optbuf), array_first(&opts), &li)) > -1) {
		switch(c) {
		case 0:
			for(unsigned int i = 0; i < array_count(&pargv); i++) {
				const struct option *opt = array_idx(&opts,li);
				param = array_idx_modifiable(&pargv,i);
				if (opt->name == param->name)
					doveadm_fill_param(param, optarg, pool);
			}
			break;
		case '?':
		case ':':
			doveadm_cmd_params_clean(&pargv);
			return -1;
		default:
			// hunt the option
			for(unsigned int i = 0; i < pargc; i++) {
				const struct option *longopt = array_idx(&opts,i);
				if (longopt->val == c)
					doveadm_fill_param(array_idx_modifiable(&pargv,i), optarg, pool);
			}
		}
	}

	/* process positional arguments */
	for(;optind<argc;optind++) {
		struct doveadm_cmd_param *ptr;
		bool found = FALSE;
		array_foreach_modifiable(&pargv, ptr) {
			if ((ptr->flags & CMD_PARAM_FLAG_POSITIONAL) != 0 &&
			    (ptr->value_set == FALSE || ptr->type == CMD_PARAM_ARRAY)) {
				doveadm_fill_param(ptr, argv[optind], pool);
				found = TRUE;
				break;
			}
		}
		if (!found) {
			i_error("Extraneous arguments found: %s",
				t_strarray_join(argv+optind, " "));
			doveadm_cmd_params_clean(&pargv);
			return -1;
		}
	}

	doveadm_cmd_params_null_terminate_arrays(&pargv);
	cctx->argv = array_get_modifiable(&pargv, &pargc);
	cctx->argc = pargc;

	cctx->cmd->cmd(cctx);

	doveadm_cmd_params_clean(&pargv);
	return 0;
}
