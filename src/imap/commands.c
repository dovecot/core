/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"

ClientCommandFunc client_command_find(const char *name)
{
	/* keep the command uppercased */
	name = str_ucase(t_strdup_noconst(name));

	switch (*name) {
	case 'A':
		if (strcmp(name, "APPEND") == 0)
			return cmd_append;
		if (strcmp(name, "AUTHENTICATE") == 0)
			return cmd_authenticate;
		break;
	case 'C':
		if (strcmp(name, "CREATE") == 0)
			return cmd_create;
		if (strcmp(name, "COPY") == 0)
			return cmd_copy;
		if (strcmp(name, "CLOSE") == 0)
			return cmd_close;
		if (strcmp(name, "CHECK") == 0)
			return cmd_check;
		if (strcmp(name, "CAPABILITY") == 0)
			return cmd_capability;
		break;
	case 'D':
		if (strcmp(name, "DELETE") == 0)
			return cmd_delete;
		break;
	case 'E':
		if (strcmp(name, "EXPUNGE") == 0)
			return cmd_expunge;
		if (strcmp(name, "EXAMINE") == 0)
			return cmd_examine;
		break;
	case 'F':
		if (strcmp(name, "FETCH") == 0)
			return cmd_fetch;
		break;
	case 'L':
		if (strcmp(name, "LIST") == 0)
			return cmd_list;
		if (strcmp(name, "LSUB") == 0)
			return cmd_lsub;
		if (strcmp(name, "LOGOUT") == 0)
			return cmd_logout;
		if (strcmp(name, "LOGIN") == 0)
			return cmd_login;
		break;
	case 'N':
		if (strcmp(name, "NOOP") == 0)
			return cmd_noop;
		break;
	case 'R':
		if (strcmp(name, "RENAME") == 0)
			return cmd_rename;
		break;
	case 'S':
		if (strcmp(name, "STORE") == 0)
			return cmd_store;
		if (strcmp(name, "SEARCH") == 0)
			return cmd_search;
		if (strcmp(name, "SORT") == 0)
			return cmd_sort;
		if (strcmp(name, "SELECT") == 0)
			return cmd_select;
		if (strcmp(name, "STATUS") == 0)
			return cmd_status;
		if (strcmp(name, "SUBSCRIBE") == 0)
			return cmd_subscribe;
		break;
	case 'U':
		if (strcmp(name, "UID") == 0)
			return cmd_uid;
		if (strcmp(name, "UNSUBSCRIBE") == 0)
			return cmd_unsubscribe;
		break;
	}

	return NULL;
}
