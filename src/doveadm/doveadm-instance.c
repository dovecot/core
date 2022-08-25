/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "master-instance.h"
#include "master-service-settings.h"
#include "doveadm.h"
#include "doveadm-print.h"

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

extern struct doveadm_cmd_ver2 doveadm_cmd_instance[];

static void instance_cmd_help(const struct doveadm_cmd_ver2 *cmd) ATTR_NORETURN;

static bool pid_file_read(const char *path, struct event *event)
{
	char buf[32];
	int fd;
	ssize_t ret;
	pid_t pid;
	bool found = FALSE;

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		if (errno != ENOENT)
			e_error(event, "open(%s) failed: %m", path);
		return FALSE;
	}

	ret = read(fd, buf, sizeof(buf));
	if (ret < 0)
		e_error(event, "read(%s) failed: %m", path);
	else if (ret > 0 && buf[ret-1] == '\n') {
		buf[ret-1] = '\0';
		if (str_to_pid(buf, &pid) == 0) {
			found = !(pid == getpid() ||
				  (kill(pid, 0) < 0 && errno == ESRCH));
		}
	}
	i_close_fd(&fd);
	return found;
}

static void cmd_instance_list(struct doveadm_cmd_context *cctx)
{
	struct master_instance_list *list;
	struct master_instance_list_iter *iter;
	const struct master_instance *inst;
	const char *instance_path, *pidfile_path;
	bool show_config = FALSE;
	const char *name = NULL;

	(void)doveadm_cmd_param_bool(cctx, "show-config", &show_config);
	(void)doveadm_cmd_param_str(cctx, "name", &name);

	if (!show_config) {
		doveadm_print_init(DOVEADM_PRINT_TYPE_TABLE);
		doveadm_print_header("path", "path", DOVEADM_PRINT_HEADER_FLAG_EXPAND);
		doveadm_print_header_simple("name");
		doveadm_print_header_simple("last used");
		doveadm_print_header_simple("running");
	}

	instance_path = t_strconcat(service_set->state_dir,
				    "/"MASTER_INSTANCE_FNAME, NULL);
	list = master_instance_list_init(instance_path);
	iter = master_instance_list_iterate_init(list);
	while ((inst = master_instance_iterate_list_next(iter)) != NULL) {
		if (name != NULL && strcmp(name, inst->name) != 0)
			continue;

		if (show_config) {
			printf("%s\n", inst->config_path == NULL ? "" :
			       inst->config_path);
			continue;
		}
		doveadm_print(inst->base_dir);
		doveadm_print(inst->name);
		doveadm_print(unixdate2str(inst->last_used));
		pidfile_path = t_strconcat(inst->base_dir, "/master.pid", NULL);
		if (pid_file_read(pidfile_path, cctx->event))
			doveadm_print("yes");
		else
			doveadm_print("no");
	}
	master_instance_iterate_list_deinit(&iter);
	master_instance_list_deinit(&list);
}

static void cmd_instance_remove(struct doveadm_cmd_context *cctx)
{
	struct master_instance_list *list;
	const struct master_instance *inst;
	const char *base_dir, *instance_path, *name;
	int ret;

	if (!doveadm_cmd_param_str(cctx, "name", &name))
		instance_cmd_help(cctx->cmd);

	instance_path = t_strconcat(service_set->state_dir,
				    "/"MASTER_INSTANCE_FNAME, NULL);
	list = master_instance_list_init(instance_path);
	inst = master_instance_list_find_by_name(list, name);
	base_dir = inst != NULL ? inst->base_dir : name;
	if ((ret = master_instance_list_remove(list, base_dir)) < 0) {
		e_error(cctx->event, "Failed to remove instance");
		doveadm_exit_code = EX_TEMPFAIL;
	} else if (ret == 0) {
		e_error(cctx->event, "Instance already didn't exist");
		doveadm_exit_code = DOVEADM_EX_NOTFOUND;
	}
	master_instance_list_deinit(&list);
}

struct doveadm_cmd_ver2 doveadm_cmd_instance[] = {
{
	.name = "instance list",
	.cmd = cmd_instance_list,
	.usage = "[-c] [<name>]",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('c', "show-config", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAM('\0', "name", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
},
{
	.name = "instance remove",
	.cmd = cmd_instance_remove,
	.usage = "<name> | <base dir>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('\0', "name", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
}
};

static void instance_cmd_help(const struct doveadm_cmd_ver2 *cmd)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(doveadm_cmd_instance); i++) {
		if (doveadm_cmd_instance[i].cmd == cmd->cmd)
			help_ver2(&doveadm_cmd_instance[i]);
	}
	i_unreached();
}

void doveadm_register_instance_commands(void)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(doveadm_cmd_instance); i++)
		doveadm_cmd_register_ver2(&doveadm_cmd_instance[i]);
}
