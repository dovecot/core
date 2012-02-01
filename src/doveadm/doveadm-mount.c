/* Copyright (c) 2012 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mountpoint-list.h"
#include "doveadm.h"
#include "doveadm-print.h"

extern struct doveadm_cmd doveadm_cmd_mount[];

static void mount_cmd_help(doveadm_command_t *cmd) ATTR_NORETURN;

static struct mountpoint_list *mountpoint_list_get(void)
{
	const char *perm_path, *state_path;

	perm_path = t_strconcat(PKG_STATEDIR"/"MOUNTPOINT_LIST_FNAME, NULL);
	state_path = t_strconcat(doveadm_settings->base_dir,
				 "/"MOUNTPOINT_LIST_FNAME, NULL);
	return mountpoint_list_init(perm_path, state_path);
}

static void cmd_mount_status(int argc, char *argv[])
{
	struct mountpoint_list *mountpoints;
	struct mountpoint_list_iter *iter;
	struct mountpoint_list_rec *rec;
	bool mounts_known;

	if (argc > 2)
		mount_cmd_help(cmd_mount_status);

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

static void cmd_mount_add(int argc, char *argv[])
{
	struct mountpoint_list *mountpoints;
	struct mountpoint_list_rec rec;
	unsigned int len;

	if (argc > 3)
		mount_cmd_help(cmd_mount_add);

	mountpoints = mountpoint_list_get();
	if (argv[1] == NULL) {
		mountpoint_list_add_missing(mountpoints, MOUNTPOINT_STATE_DEFAULT,
					    mountpoint_list_default_ignore_types);
	} else {
		memset(&rec, 0, sizeof(rec));
		rec.mount_path = argv[1];
		rec.state = argv[2] != NULL ? argv[2] :
			MOUNTPOINT_STATE_DEFAULT;

		len = strlen(rec.mount_path);
		if (len > 0 && rec.mount_path[len-1] == '*') {
			rec.wildcard = TRUE;
			rec.mount_path = t_strndup(rec.mount_path, len-1);
		}
		mountpoint_list_add(mountpoints, &rec);
	}
	(void)mountpoint_list_save(mountpoints);
	mountpoint_list_deinit(&mountpoints);
}

static void cmd_mount_remove(int argc, char *argv[])
{
	struct mountpoint_list *mountpoints;

	if (argc != 2)
		mount_cmd_help(cmd_mount_remove);

	mountpoints = mountpoint_list_get();
	if (!mountpoint_list_remove(mountpoints, argv[1]))
		i_error("Mountpoint not found: %s", argv[1]);
	else
		(void)mountpoint_list_save(mountpoints);
	mountpoint_list_deinit(&mountpoints);
}

struct doveadm_cmd doveadm_cmd_mount[] = {
	{ cmd_mount_status, "mount status", "[<path>]" },
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
