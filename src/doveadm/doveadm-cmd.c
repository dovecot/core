/* Copyright (c) 2009-2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "str.h"
#include "doveadm-cmd.h"
#include "doveadm.h"

#include <stdio.h>
#include <unistd.h>
#include <getopt.h>

static struct doveadm_cmd *doveadm_commands[] = {
	&doveadm_cmd_who,
	&doveadm_cmd_penalty,
	&doveadm_cmd_kick,
	&doveadm_cmd_mailbox_mutf7,
	&doveadm_cmd_sis_deduplicate,
	&doveadm_cmd_sis_find,
	&doveadm_cmd_stats_dump
};

static struct doveadm_cmd_ver2 *doveadm_commands_ver2[] = {
	&doveadm_cmd_stop_ver2,
	&doveadm_cmd_reload_ver2
};

ARRAY_TYPE(doveadm_cmd) doveadm_cmds;
ARRAY_TYPE(doveadm_cmd_ver2) doveadm_cmds_ver2;
ARRAY_DEFINE_TYPE(getopt_option_array, struct option);

void doveadm_register_cmd(const struct doveadm_cmd *cmd)
{
	array_append(&doveadm_cmds, cmd, 1);
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
	array_append(&doveadm_cmds_ver2, cmd, 1);
}

const struct doveadm_cmd_ver2* doveadm_cmd_find_ver2(const char *cmd_name,
	int argc, const char *argv[])
{
	int i;
	const struct doveadm_cmd_ver2 *cmd;
	const char *cptr;

	for(i=0;i<argc;i++) {
		if (strcmp(argv[i],cmd_name)==0) break;
	}

	i_assert(i != argc);

	array_foreach(&doveadm_cmds_ver2, cmd) {
		cptr = cmd->name;
		/* cannot reuse i here because this needs be
		   done more than once */
		for(int k=0; cptr != NULL && i+k < argc; k++) {
			size_t alen = strlen(argv[i+k]);
			/* make sure we don't overstep */
			if (strlen(cptr) < alen) break;
			/* did not match */
			if (strncmp(cptr, argv[i+k], alen) != 0) break;
			/* do not accept abbreviations */
			if (cptr[alen] != ' ' && cptr[alen] != '\0') break;
			cptr += alen;
			if (*cptr != '\0') cptr++; /* consume space */
		}
		/* name was fully consumed */
		if (*cptr == '\0') return cmd;
	}

	return NULL;
}

static const struct doveadm_cmd *
doveadm_cmd_find_multi_word(const struct doveadm_cmd *cmd,
			    const char *cmdname, int *_argc, char **_argv[])
{
	int argc = *_argc;
	char **argv = *_argv;
	const struct doveadm_cmd *subcmd;
	unsigned int len;

	if (argc < 2)
		return NULL;

	len = strlen(argv[1]);
	if (strncmp(cmdname, argv[1], len) != 0)
		return NULL;

	argc--; argv++;
	if (cmdname[len] == ' ') {
		/* more args */
		subcmd = doveadm_cmd_find_multi_word(cmd, cmdname + len + 1,
						     &argc, &argv);
		if (subcmd == NULL)
			return NULL;
	} else {
		if (cmdname[len] != '\0')
			return NULL;
	}

	*_argc = argc;
	*_argv = argv;
	return cmd;
}

const struct doveadm_cmd *
doveadm_cmd_find(const char *cmd_name, int *argc, char **argv[])
{
	const struct doveadm_cmd *cmd, *subcmd;
	unsigned int cmd_name_len;

	i_assert(*argc > 0);

	cmd_name_len = strlen(cmd_name);
	array_foreach(&doveadm_cmds, cmd) {
		if (strcmp(cmd->name, cmd_name) == 0)
			return cmd;

		/* see if it matches a multi-word command */
		if (strncmp(cmd->name, cmd_name, cmd_name_len) == 0 &&
		    cmd->name[cmd_name_len] == ' ') {
			const char *subcmd_name = cmd->name + cmd_name_len + 1;

			subcmd = doveadm_cmd_find_multi_word(cmd, subcmd_name,
							     argc, argv);
			if (subcmd != NULL)
				return subcmd;
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

	doveadm_register_auth_commands();
	doveadm_register_director_commands();
	doveadm_register_instance_commands();
	doveadm_register_mount_commands();
	doveadm_register_proxy_commands();
	doveadm_register_log_commands();
	doveadm_register_replicator_commands();
	doveadm_register_dict_commands();
	doveadm_register_fs_commands();
}

void doveadm_cmds_deinit(void)
{
	array_free(&doveadm_cmds);
}

static const struct doveadm_cmd_param*
doveadm_cmd_param_get(int argc, const struct doveadm_cmd_param* params, const char *name)
{
	i_assert(params != NULL);
	for(int i = 0; i < argc; i++) {
		if (strcmp(params[i].name, name) == 0 && params[i].value_set)
			return &(params[i]);
	}
	return NULL;
}

bool doveadm_cmd_param_bool(int argc, const struct doveadm_cmd_param* params, const char *name, bool* value)
{
	const struct doveadm_cmd_param* param;
	if ((param = doveadm_cmd_param_get(argc, params, name))==NULL) return FALSE;

	if (param->type == CMD_PARAM_NONE || param->type == CMD_PARAM_BOOL) {
		*value = param->value.v_bool;
		return TRUE;
	}
	return FALSE;
}

bool doveadm_cmd_param_int64(int argc, const struct doveadm_cmd_param* params, const char *name, int64_t* value)
{
	const struct doveadm_cmd_param* param;
	if ((param = doveadm_cmd_param_get(argc, params, name))==NULL) return FALSE;

	if (param->type == CMD_PARAM_INT64) {
		*value = param->value.v_int64;
		return TRUE;
	}
	return FALSE;
}

bool doveadm_cmd_param_str(int argc, const struct doveadm_cmd_param* params, const char *name, const char** value)
{
	const struct doveadm_cmd_param* param;
	if ((param = doveadm_cmd_param_get(argc, params, name))==NULL) return FALSE;

	if (param->type == CMD_PARAM_STR) {
		*value = param->value.v_string;
		return TRUE;
	}
	return FALSE;
}

bool doveadm_cmd_param_array(int argc, struct doveadm_cmd_param* params, const char *name, ARRAY_TYPE(const_string)** value)
{
	const struct doveadm_cmd_param* param;
	if ((param = doveadm_cmd_param_get(argc, params, name))==NULL) return FALSE;
	if (param->type == CMD_PARAM_STR) {
		*value = (ARRAY_TYPE(const_string)*)&(param->value.v_array);
		return TRUE;
	}
	return FALSE;
}

bool doveadm_cmd_param_istream(int argc, struct doveadm_cmd_param* params, const char *name, struct istream** value)
{
	const struct doveadm_cmd_param* param;
	if ((param = doveadm_cmd_param_get(argc, params, name))==NULL) return FALSE;

	if (param->type == CMD_PARAM_ISTREAM) {
		*value = param->value.v_istream;
		return TRUE;
	}
	return FALSE;
}

static void
doveadm_cmd_params_to_argv(const char *name, int pargc, const struct doveadm_cmd_param* params,
	ARRAY_TYPE(const_string) *argv)
{
	int i;
	const char * const * cptr;
	i_assert(array_count(argv) == 0);
	array_append(argv, &name, 1);
	for(i=0;i<pargc;i++) {
		if (params[i].value_set && params[i].opt != NULL &&
			*(params[i].opt) != ':' && *(params[i].opt) != '?') {
			const char *optarg = t_strdup_printf("-%c", params[i].opt[0]);
			if (params[i].type == CMD_PARAM_STR) {
	                        array_append(argv, &optarg, 1);
				array_append(argv, &params[i].value.v_string,1);
			} else if (params[i].type == CMD_PARAM_ARRAY) {
				array_foreach(&params[i].value.v_array, cptr) {
					array_append(argv, &optarg, 1);
					array_append(argv, cptr, 1);
				}
			}
		} else if (params[i].value_set) {
			if (params[i].type == CMD_PARAM_ARRAY) {
				array_append_array(argv, &params[i].value.v_array);
			} else {
				array_append(argv, &params[i].value.v_string,1);
			}
		}
	}
	array_append_zero(argv);
}

int
doveadm_cmd_ver2_to_cmd_wrapper(const struct doveadm_cmd_ver2* cmd,
	int argc, const struct doveadm_cmd_param* param)
{
	unsigned int pargc;
	const char **pargv;

	i_assert(cmd->old_cmd != NULL);

	ARRAY_TYPE(const_string) nargv;
	t_array_init(&nargv, 8);
	doveadm_cmd_params_to_argv(cmd->name, argc, param, &nargv);
	pargv = array_get_modifiable(&nargv, &pargc);
	i_getopt_reset();
	cmd->old_cmd(pargc-1, (char**)pargv);

	return 0;
}

static void
doveadm_build_options(const struct doveadm_cmd_param par[],
		string_t *shortopts,
		ARRAY_TYPE(getopt_option_array) *longopts)
{
	const char *optp;
	for(size_t i=0; par[i].name != NULL; i++) {
		struct option longopt;
		if ((par[i].flags & CMD_PARAM_FLAG_DO_NOT_EXPOSE) != 0) continue;
		longopt.name = par[i].name;
		longopt.flag = 0;
		longopt.val = 0;
		if (par[i].opt) {
			optp = par[i].opt;
			if (*optp != ':' && *optp != '?') {
				longopt.val = *optp;
				str_append_c(shortopts, *optp);
				optp++;
				if (optp[0] != '\0')
					str_append_c(shortopts, *optp);
			}
			switch(*optp) {
			case ':': longopt.has_arg = 1; break;
			case '?': longopt.has_arg = 2; break;
			default:
				longopt.has_arg = 0;
			}
		} else {
			longopt.has_arg = 0;
		}
		array_append(longopts, &longopt, 1);
	}
	array_append_zero(longopts);
}

static void doveadm_fill_param(struct doveadm_cmd_param *param,
	const char *value, pool_t pool)
{
	param->value_set = TRUE;
	switch(param->type) {
	case CMD_PARAM_NONE:
	case CMD_PARAM_BOOL:
		param->value.v_bool = TRUE; break;
	case CMD_PARAM_INT64:
		if (str_to_int64(value, &param->value.v_int64) != 0) {
			param->value_set = FALSE;
		}
		break;
	case CMD_PARAM_STR:
		if (value != NULL) {
			param->value.v_string = p_strdup(pool, value);
		} else {
			param->value.v_string = NULL;
		}
		break;
	case CMD_PARAM_ARRAY:
		if (!array_is_created(&param->value.v_array))
			p_array_init(&param->value.v_array, pool, 8);
		const char *val = p_strdup(pool, value);
		array_append(&param->value.v_array, &val, 1);
		break;
	case CMD_PARAM_ISTREAM: {
		struct istream *is;
		if (strcmp(value,"-") == 0) {
			is = i_stream_create_fd(STDIN_FILENO, IO_BLOCK_SIZE, FALSE);
		} else {
			is = i_stream_create_file(value, IO_BLOCK_SIZE);
		}
		param->value.v_istream = is;
	}
	}
}

bool doveadm_cmd_try_run_ver2(const char *cmd_name, int argc, const char *argv[])
{
	const struct doveadm_cmd_ver2 *cmd;

	cmd = doveadm_cmd_find_ver2(cmd_name, argc, argv);
	if (cmd == NULL)
		return FALSE;

	if (doveadm_cmd_run_ver2(cmd, argc, argv) < 0)
		doveadm_exit_code = EX_USAGE;
	return TRUE;
}

int doveadm_cmd_run_ver2(const struct doveadm_cmd_ver2 *cmd, int argc, const char *argv[])
{
	struct doveadm_cmd_param *param;
	ARRAY(struct doveadm_cmd_param) pargv;
	ARRAY_TYPE(getopt_option_array) opts;
	const char *cptr;
	unsigned int pargc;
	int c,li;
	pool_t pool = pool_datastack_create();
	string_t *optbuf = str_new(pool, 64);

	p_array_init(&opts, pool, 4);

	// build parameters
	doveadm_build_options(cmd->parameters, optbuf, &opts);

	p_array_init(&pargv, pool, 20);

	for(pargc=0;cmd->parameters[pargc].name != NULL;pargc++) {
		param = array_append_space(&pargv);
		memcpy(param, &(cmd->parameters[pargc]), sizeof(struct doveadm_cmd_param));
		param->value_set = FALSE;
	}
	i_assert(pargc == array_count(&opts)-1); /* opts is NULL-terminated */

	while((c = getopt_long(argc, (char*const*)argv, str_c(optbuf), array_idx(&opts, 0), &li)) > -1) {
		switch(c) {
		case 0:
			doveadm_fill_param(array_idx_modifiable(&pargv,li), optarg, pool);
			break;
		case '?':
		case ':':
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

	cptr = cmd->name;
	while((cptr = strchr(cptr+1, ' ')) != NULL) optind++;

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
			i_error("Extraneous arguments found");
			return -1;
		}
	}

	param = array_get_modifiable(&pargv, &pargc);

	// FIXME: Unsure what do to with return value
	cmd->cmd(cmd, pargc, param);

	// unref istreams
	array_foreach_modifiable(&pargv, param) {
		if (param->type == CMD_PARAM_ISTREAM && param->value.v_istream != NULL)
			i_stream_unref(&param->value.v_istream);
	}
	return 0;
}
