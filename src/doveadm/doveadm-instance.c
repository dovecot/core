/* Copyright (c) 2012 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "master-instance.h"
#include "doveadm.h"
#include "doveadm-print.h"

#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

extern struct doveadm_cmd doveadm_cmd_instance[];

static void instance_cmd_help(doveadm_command_t *cmd) ATTR_NORETURN;

static bool pid_file_read(const char *path)
{
	char buf[32];
	int fd;
	ssize_t ret;
	pid_t pid;
	bool found = FALSE;

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		if (errno != ENOENT)
			i_error("open(%s) failed: %m", path);
		return FALSE;
	}

	ret = read(fd, buf, sizeof(buf));
	if (ret < 0)
		i_error("read(%s) failed: %m", path);
	else if (ret > 0 && buf[ret-1] == '\n') {
		buf[ret-1] = '\0';
		if (str_to_pid(buf, &pid) == 0) {
			found = !(pid == getpid() ||
				  (kill(pid, 0) < 0 && errno == ESRCH));
		}
	}
	(void)close(fd);
	return found;
}

static void cmd_instance_list(int argc ATTR_UNUSED, char *argv[] ATTR_UNUSED)
{
	struct master_instance_list *list;
	struct master_instance_list_iter *iter;
	const struct master_instance *inst;
	const char *pidfile_path;

	doveadm_print_init(DOVEADM_PRINT_TYPE_TABLE);
	doveadm_print_header("path", "path", DOVEADM_PRINT_HEADER_FLAG_EXPAND);
	doveadm_print_header_simple("name");
	doveadm_print_header_simple("running");

	list = master_instance_list_init(MASTER_INSTANCE_PATH);
	iter = master_instance_list_iterate_init(list);
	while ((inst = master_instance_iterate_list_next(iter)) != NULL) {
		doveadm_print(inst->base_dir);
		doveadm_print(inst->name);
		pidfile_path = t_strconcat(inst->base_dir, "/master.pid", NULL);
		if (pid_file_read(pidfile_path))
			doveadm_print("yes");
		else
			doveadm_print("no");
	}
	master_instance_iterate_list_deinit(&iter);
	master_instance_list_deinit(&list);
}

static void cmd_instance_remove(int argc, char *argv[])
{
	struct master_instance_list *list;
	int ret;

	if (argc != 2)
		instance_cmd_help(cmd_instance_remove);

	list = master_instance_list_init(MASTER_INSTANCE_PATH);
	if ((ret = master_instance_list_remove(list, argv[1])) < 0)
		i_error("Failed to remove instance");
	else if (ret == 0)
		i_error("Instance already didn't exist");
	master_instance_list_deinit(&list);
}

struct doveadm_cmd doveadm_cmd_instance[] = {
	{ cmd_instance_list, "instance list", "" },
	{ cmd_instance_remove, "instance remove", "<base dir>" }
};

static void instance_cmd_help(doveadm_command_t *cmd)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(doveadm_cmd_instance); i++) {
		if (doveadm_cmd_instance[i].cmd == cmd)
			help(&doveadm_cmd_instance[i]);
	}
	i_unreached();
}

void doveadm_register_instance_commands(void)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(doveadm_cmd_instance); i++)
		doveadm_register_cmd(&doveadm_cmd_instance[i]);
}
