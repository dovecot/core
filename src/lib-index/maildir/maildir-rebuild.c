/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "maildir-index.h"
#include "mail-index-data.h"
#include "mail-index-util.h"
#include "mail-hash.h"

#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>

int maildir_index_rebuild(MailIndex *index)
{
	struct stat st;
	const char *cur_dir, *new_dir;

	i_assert(index->lock_type != MAIL_LOCK_SHARED);

	if (!mail_index_set_lock(index, MAIL_LOCK_EXCLUSIVE))
		return FALSE;

	/* reset the header */
	mail_index_init_header(index->header);

	/* update indexid, which also means that our state has completely
	   changed */
	index->indexid = index->header->indexid;
	index->inconsistent = TRUE;

	if (msync(index->mmap_base, sizeof(MailIndexHeader), MS_SYNC) < 0)
		return FALSE;

	/* reset data file */
	if (!mail_index_data_reset(index->data))
		return FALSE;

	/* rebuild cur/ directory */
	cur_dir = t_strconcat(index->dir, "/cur", NULL);
	if (!maildir_index_build_dir(index, cur_dir, NULL))
		return FALSE;

	/* also see if there's new mail */
	new_dir = t_strconcat(index->dir, "/new", NULL);
	if (!maildir_index_build_dir(index, new_dir, cur_dir))
		return FALSE;

	/* update sync stamp */
	if (stat(cur_dir, &st) < 0)
		return index_file_set_syscall_error(index, cur_dir, "stat()");

	index->file_sync_stamp = st.st_mtime;

	/* rebuild is complete - remove the flag */
	index->header->flags &= ~(MAIL_INDEX_FLAG_REBUILD|MAIL_INDEX_FLAG_FSCK);
	return TRUE;
}
