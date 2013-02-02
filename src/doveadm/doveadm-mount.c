/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "master-service-settings.h"
#include "mountpoint-list.h"
#include "doveadm.h"
#include "doveadm-print.h"

extern struct doveadm_cmd doveadm_cmd_mount[];

static void mount_cmd_help(doveadm_command_t *cmd) ATTR_NORETURN;

static struct mountpoint_list *mountpoint_list_get(void)
{
	const char *perm_path, *state_path;

	perm_path = t_strconcat(service_set->state_dir,
				 "/"MOUNTPOINT_LIST_FNAME, NULL);
	state_path = t_strconcat(service_set->base_dir,
				 "/"MOUNTPOINT_LIST_FNAME, NULL);
	return mountpoint_list_init(perm_path, state_path);
}

static void cmd_mount_list(int argc, char *argv[])
{
	struct mountpoint_list *mountpoints;
	struct mountpoint_list_iter *iter;
	struct mountpoint_list_rec *rec;
	bool mounts_known;

	if (argc > 2)
		mount_cmd_help(cmd_mount_list);

	doveadm_print_init(DOVEADM_PRINT_TYPE_TABLE);
	doveadm_print_header_simple(" ");
	doveadm_print_header("path", "path", DOVEADM_PRINT_HEADER_FLAG_EXPAND);
	doveadm_print_header_simple("state");

	mountpoints = mountpoint_list_get();
	mounts_known = mountpoint_list_update_mounted(mountpoints) == 0;
	iter = mountpoint_list_iter_init(mountpoints);
	while ((rec = mountpoint_list_iter_next(iter)) != NULL) {
		if (argv[1] != NULL && strcmp(argv[1], rec->mount_path) != 0)
			continue;

		if (mounts_known && MOUNTPOINT_WRONGLY_NOT_MOUNTED(rec))
			doveadm_print("!");
		else
			doveadm_print(" ");
		doveadm_print(!rec->wildcard ? rec->mount_path :
			      t_strconcat(rec->mount_path, "*", NULL));

		doveadm_print(rec->state);
	}
	mountpoint_list_iter_deinit(&iter);
	mountpoint_list_deinit(&mountpoints);
}

static bool mount_path_get_wildcard(const char **path)
{
	unsigned int len;

	len = strlen(*path);
	if (len > 0 && (*path)[len-1] == '*') {
		*path = t_strndup(*path, len-1);
		return TRUE;
	} else {
		return FALSE;
	}
}

static void cmd_mount_add(int argc, char *argv[])
{
	struct mountpoint_list *mountpoints;
	struct mountpoint_list_rec rec;
	int ret = 0;

	if (argc > 3)
		mount_cmd_help(cmd_mount_add);

	mountpoints = mountpoint_list_get();
	if (argv[1] == NULL) {
		ret = mountpoint_list_add_missing(mountpoints,
			MOUNTPOINT_STATE_DEFAULT,
			mountpoint_list_default_ignore_prefixes,
			mountpoint_list_default_ignore_types);
	} else {
		memset(&rec, 0, sizeof(rec));
		rec.mount_path = argv[1];
		rec.state = argv[2] != NULL ? argv[2] :
			MOUNTPOINT_STATE_DEFAULT;

		if (mount_path_get_wildcard(&rec.mount_path))
			rec.wildcard = TRUE;
		mountpoint_list_add(mountpoints, &rec);
	}
	if (mountpoint_list_save(mountpoints) < 0)
		ret = -1;
	mountpoint_list_deinit(&mountpoints);
	if (ret < 0)
		doveadm_exit_code = EX_TEMPFAIL;
}

static void cmd_mount_remove(int argc, char *argv[])
{
	struct mountpoint_list *mountpoints;
	const char *mount_path;

	if (argc != 2)
		mount_cmd_help(cmd_mount_remove);

	mount_path = argv[1];
	(void)mount_path_get_wildcard(&mount_path);

	mountpoints = mountpoint_list_get();
	if (!mountpoint_list_remove(mountpoints, mount_path))
		i_error("Mountpoint not found: %s", mount_path);
	else
		(void)mountpoint_list_save(mountpoints);
	mountpoint_list_deinit(&mountpoints);
}

struct doveadm_cmd doveadm_cmd_mount[] = {
	{ cmd_mount_list, "mount list", "[<path>]" },
	{ cmd_mount_add, "mount add", "[<path> [<state>]]" },
	{ cmd_mount_remove, "mount remove", "<path>" }
};

static void mount_cmd_help(doveadm_command_t *cmd)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(doveadm_cmd_mount); i++) {
		if (doveadm_cmd_mount[i].cmd == cmd)
			help(&doveadm_cmd_mount[i]);
	}
	i_unreached();
}

void doveadm_register_mount_commands(void)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(doveadm_cmd_mount); i++)
		doveadm_register_cmd(&doveadm_cmd_mount[i]);
}
