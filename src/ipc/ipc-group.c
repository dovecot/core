/* Copyright (c) 2011-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ipc-connection.h"
#include "ipc-group.h"

struct ipc_group_cmd {
	ipc_cmd_callback_t *callback;
	void *context;

	int refcount;
	char *first_error;
};

static ARRAY(struct ipc_group *) ipc_groups;

struct ipc_group *ipc_group_alloc(int listen_fd)
{
	struct ipc_group *group;

	i_assert(ipc_group_lookup_listen_fd(listen_fd) == NULL);

	group = i_new(struct ipc_group, 1);
	group->listen_fd = listen_fd;
	array_append(&ipc_groups, &group, 1);
	return group;
}

void ipc_group_free(struct ipc_group **_group)
{
	struct ipc_group *const *groups, *group = *_group;
	unsigned int i, count;

	i_assert(group->connections == NULL);

	*_group = NULL;
	groups = array_get(&ipc_groups, &count);
	for (i = 0; i < count; i++) {
		if (groups[i] == group) {
			array_delete(&ipc_groups, i, 1);
			break;
		}
	}
	i_free(group->name);
	i_free(group);
}

struct ipc_group *ipc_group_lookup_listen_fd(int listen_fd)
{
	struct ipc_group *const *groupp;

	array_foreach(&ipc_groups, groupp) {
		if ((*groupp)->listen_fd == listen_fd)
			return *groupp;
	}
	return NULL;
}

struct ipc_group *ipc_group_lookup_name(const char *name)
{
	struct ipc_group *const *groupp;

	array_foreach(&ipc_groups, groupp) {
		if ((*groupp)->name != NULL &&
		    strcmp((*groupp)->name, name) == 0)
			return *groupp;
	}
	return NULL;
}

int ipc_group_update_name(struct ipc_group *group, const char *name)
{
	if (group->name == NULL)
		group->name = i_strdup(name);
	else if (strcmp(group->name, name) != 0)
		return -1;
	return 0;
}

static void ipc_group_cmd_callback(enum ipc_cmd_status status,
				   const char *line, void *context)
{
	struct ipc_group_cmd *group_cmd = context;

	i_assert(group_cmd->refcount > 0);

	switch (status) {
	case IPC_CMD_STATUS_REPLY:
		group_cmd->callback(IPC_CMD_STATUS_REPLY, line,
				    group_cmd->context);
		break;
	case IPC_CMD_STATUS_ERROR:
		if (group_cmd->first_error == NULL)
			group_cmd->first_error = i_strdup(line);
		/* fall through */
	case IPC_CMD_STATUS_OK:
		if (--group_cmd->refcount > 0)
			break;

		if (group_cmd->first_error == NULL) {
			group_cmd->callback(IPC_CMD_STATUS_OK, line,
					    group_cmd->context);
		} else {
			group_cmd->callback(IPC_CMD_STATUS_ERROR,
					    group_cmd->first_error,
					    group_cmd->context);
			i_free(group_cmd->first_error);
		}
		i_free(group_cmd);
		break;
	}

}

bool ipc_group_cmd(struct ipc_group *group, const char *cmd,
		   ipc_cmd_callback_t *callback, void *context)
{
	struct ipc_connection *conn, *next;
	struct ipc_group_cmd *group_cmd;

	if (group->connections == NULL) {
		callback(IPC_CMD_STATUS_OK, NULL, context);
		return FALSE;
	}

	group_cmd = i_new(struct ipc_group_cmd, 1);
	group_cmd->callback = callback;
	group_cmd->context = context;

	for (conn = group->connections; conn != NULL; conn = next) {
		next = conn->next;

		group_cmd->refcount++;
		ipc_connection_cmd(conn, cmd,
				   ipc_group_cmd_callback, group_cmd);
	}
	return TRUE;
}

void ipc_groups_init(void)
{
	i_array_init(&ipc_groups, 16);
}

void ipc_groups_deinit(void)
{
	struct ipc_group *const *groupp, *group;

	while (array_count(&ipc_groups) > 0) {
		groupp = array_first(&ipc_groups);
		group = *groupp;

		while ((*groupp)->connections != NULL) {
			struct ipc_connection *conn = (*groupp)->connections;
			ipc_connection_destroy(&conn, FALSE, "Shutting down");
		}
		ipc_group_free(&group);
	}
	array_free(&ipc_groups);
}
