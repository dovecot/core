/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "iobuffer.h"
#include "maildir-index.h"
#include "mail-index-util.h"

#include <unistd.h>
#include <fcntl.h>

IOBuffer *maildir_open_mail(MailIndex *index, MailIndexRecord *rec)
{
	const char *fname, *path;
	int fd;

	fname = index->lookup_field(index, rec, FIELD_TYPE_LOCATION);
	if (fname == NULL) {
                INDEX_MARK_CORRUPTED(index);
		index_set_error(index, "Corrupted index file %s: "
				"Missing location field for record %u",
				index->filepath, rec->uid);
		return NULL;
	}

	path = t_strconcat(index->dir, "/cur/", fname, NULL);

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		index_set_error(index, "Error opening mail file %s: %m", path);
		return NULL;
	}

	return io_buffer_create_mmap(fd, default_pool, MAIL_MMAP_BLOCK_SIZE, 0);
}
