/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "index-storage.h"

#include <stdlib.h>
#include <sys/stat.h>

static int check_interval = -1;

static void check_timeout(void *context, Timeout timeout __attr_unused__)
{
	IndexMailbox *ibox = context;
	struct stat st;

	if (ioloop_time - ibox->last_check < check_interval)
		return;

	ibox->last_check = ioloop_time;
	if (stat(ibox->check_path, &st) == 0 &&
	    ibox->check_file_stamp != st.st_mtime) {
		ibox->check_file_stamp = st.st_mtime;
		ibox->box.sync(&ibox->box, FALSE);
	}
}

void index_mailbox_check_add(IndexMailbox *ibox, const char *path)
{
	const char *str;
	struct stat st;

	if (check_interval < 0) {
		str = getenv("MAILBOX_CHECK_INTERVAL");
		check_interval = str == NULL ? 0 : atoi(str);
		if (check_interval < 0)
			check_interval = 0;
	}

	if (check_interval == 0)
		return;

	ibox->check_path = i_strdup(path);
	ibox->check_file_stamp = stat(path, &st) < 0 ? 0 : st.st_mtime;
	ibox->check_to = timeout_add(1000, check_timeout, ibox);
}

void index_mailbox_check_remove(IndexMailbox *ibox)
{
	if (ibox->check_to != NULL)
		timeout_remove(ibox->check_to);
	i_free(ibox->check_path);
}
