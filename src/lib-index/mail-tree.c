/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "mmap-util.h"
#include "file-set-size.h"
#include "write-full.h"
#include "mail-index.h"
#include "mail-index-util.h"
#include "mail-tree.h"

#include <unistd.h>
#include <fcntl.h>

#define MAIL_TREE_INITIAL_SIZE \
	(sizeof(MailTreeHeader) + sizeof(MailTreeNode) * 64)

#define TREE_GROW_SIZE \
	(sizeof(MailTreeNode) * 64)

static int tree_set_syscall_error(MailTree *tree, const char *function)
{
	i_assert(function != NULL);

	index_set_error(tree->index, "%s failed with binary tree file %s: %m",
			function, tree->filepath);
	return FALSE;
}

int _mail_tree_set_corrupted(MailTree *tree, const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	t_push();

	index_set_error(tree->index, "Corrupted binary tree file %s: %s",
			tree->filepath, t_strdup_vprintf(fmt, va));

	t_pop();
	va_end(va);

	/* make sure we don't get back here */
	tree->index->inconsistent = TRUE;
	(void)unlink(tree->filepath);

	return FALSE;
}

static int mmap_update(MailTree *tree, int forced)
{
	if (!forced && tree->header != NULL &&
	    tree->mmap_full_length >= tree->header->used_file_size) {
		tree->mmap_used_length = tree->header->used_file_size;
		return TRUE;
	}

	i_assert(!tree->anon_mmap);

	if (tree->mmap_base != NULL) {
		/* make sure we're synced before munmap() */
		if (tree->modified &&
		    msync(tree->mmap_base, tree->mmap_used_length, MS_SYNC) < 0)
			return tree_set_syscall_error(tree, "msync()");

		if (munmap(tree->mmap_base, tree->mmap_full_length) < 0)
			tree_set_syscall_error(tree, "munmap()");
	}

	tree->mmap_used_length = 0;
	tree->header = NULL;
	tree->node_base = NULL;

	tree->mmap_base = mmap_rw_file(tree->fd, &tree->mmap_full_length);
	if (tree->mmap_base == MAP_FAILED) {
		tree->mmap_base = NULL;
		return tree_set_syscall_error(tree, "mmap()");
	}

	return TRUE;
}

static int mmap_verify(MailTree *tree)
{
	MailTreeHeader *hdr;
	unsigned int extra;

	if (tree->mmap_full_length <
	    sizeof(MailTreeHeader) + sizeof(MailTreeNode)) {
		index_set_error(tree->index, "Too small binary tree file %s",
				tree->filepath);
		(void)unlink(tree->filepath);
		return FALSE;
	}

	extra = (tree->mmap_full_length - sizeof(MailTreeHeader)) %
		sizeof(MailTreeNode);

	if (extra != 0) {
		/* partial write or corrupted -
		   truncate the file to valid length */
		tree->mmap_full_length -= extra;
		if (ftruncate(tree->fd, (off_t)tree->mmap_full_length) < 0)
			tree_set_syscall_error(tree, "ftruncate()");
	}

	hdr = tree->mmap_base;
	if (hdr->used_file_size > tree->mmap_full_length) {
		_mail_tree_set_corrupted(tree,
			"used_file_size larger than real file size "
			"(%"PRIuUOFF_T" vs %"PRIuSIZE_T")",
			hdr->used_file_size, tree->mmap_full_length);
		return FALSE;
	}

	if ((hdr->used_file_size - sizeof(MailTreeHeader)) %
	    sizeof(MailTreeNode) != 0) {
		_mail_tree_set_corrupted(tree,
			"Invalid used_file_size in header (%"PRIuUOFF_T")",
			hdr->used_file_size);
		return FALSE;
	}

	tree->header = tree->mmap_base;
	tree->node_base = (MailTreeNode *) ((char *) tree->mmap_base +
					    sizeof(MailTreeHeader));
	tree->mmap_used_length = hdr->used_file_size;
	return TRUE;
}

static MailTree *mail_tree_open(MailIndex *index)
{
	MailTree *tree;
	const char *path;
	int fd;

	path = t_strconcat(index->filepath, ".tree", NULL);
	fd = open(path, O_RDWR | O_CREAT, 0660);
	if (fd == -1) {
		if (errno == ENOSPC)
			index->nodiskspace = TRUE;

		index_file_set_syscall_error(index, path, "open()");
		return NULL;
	}

	tree = i_new(MailTree, 1);
	tree->fd = fd;
	tree->index = index;
	tree->filepath = i_strdup(path);

	index->tree = tree;
	return tree;
}

static void mail_tree_close(MailTree *tree)
{
	if (tree->anon_mmap) {
		if (munmap_anon(tree->mmap_base, tree->mmap_full_length) < 0)
			tree_set_syscall_error(tree, "munmap_anon()");
	} else if (tree->mmap_base != NULL) {
		if (munmap(tree->mmap_base, tree->mmap_full_length) < 0)
			tree_set_syscall_error(tree, "munmap()");
	}
	tree->mmap_base = NULL;
	tree->mmap_full_length = 0;
	tree->mmap_used_length = 0;
	tree->header = NULL;

	if (tree->fd != -1) {
		if (close(tree->fd) < 0)
			tree_set_syscall_error(tree, "close()");
		tree->fd = -1;
	}

	i_free(tree->filepath);
}

int mail_tree_create(MailIndex *index)
{
	MailTree *tree;

	i_assert(index->lock_type == MAIL_LOCK_EXCLUSIVE);

	tree = mail_tree_open(index);
	if (tree == NULL)
		return FALSE;

	if (!mail_tree_rebuild(tree)) {
		mail_tree_free(tree);
		return FALSE;
	}

	return TRUE;
}

int mail_tree_open_or_create(MailIndex *index)
{
	MailTree *tree;

	tree = mail_tree_open(index);
	if (tree == NULL)
		return FALSE;

	do {
		if (!mmap_update(tree, TRUE))
			break;

		if (tree->mmap_full_length == 0) {
			/* just created it */
			if (!mail_tree_rebuild(tree))
				break;
		} else if (!mmap_verify(tree)) {
			/* broken header */
			if (!mail_tree_rebuild(tree))
				break;
		} else if (tree->header->indexid != index->indexid) {
			index_set_error(tree->index,
				"IndexID mismatch for binary tree file %s",
				tree->filepath);

			if (!mail_tree_rebuild(tree))
				break;
		}

		return TRUE;
	} while (0);

	mail_tree_free(tree);
	return FALSE;
}

void mail_tree_free(MailTree *tree)
{
	tree->index->tree = NULL;

	mail_tree_close(tree);
	i_free(tree);
}

static int mail_tree_init(MailTree *tree)
{
        MailTreeHeader hdr;

	/* first node is always used, and is the RBNULL node */
	memset(&hdr, 0, sizeof(MailTreeHeader));
	hdr.indexid = tree->index->indexid;
	hdr.used_file_size = sizeof(MailTreeHeader) + sizeof(MailTreeNode);

	if (lseek(tree->fd, 0, SEEK_SET) < 0)
		return tree_set_syscall_error(tree, "lseek()");

	if (write_full(tree->fd, &hdr, sizeof(hdr)) < 0) {
		if (errno == ENOSPC)
			tree->index->nodiskspace = TRUE;

		return tree_set_syscall_error(tree, "write_full()");
	}

	if (file_set_size(tree->fd, MAIL_TREE_INITIAL_SIZE) < 0) {
		if (errno == ENOSPC)
			tree->index->nodiskspace = TRUE;

		return tree_set_syscall_error(tree, "file_set_size()");
	}

	return TRUE;
}

int mail_tree_rebuild(MailTree *tree)
{
	MailIndexRecord *rec;

	if (!tree->index->set_lock(tree->index, MAIL_LOCK_EXCLUSIVE))
		return FALSE;

	if (!mail_tree_init(tree) ||
	    !mmap_update(tree, TRUE) ||
	    !mmap_verify(tree)) {
		tree->index->header->flags |= MAIL_INDEX_FLAG_REBUILD_TREE;
		return FALSE;
	}

	rec = tree->index->lookup(tree->index, 1);
	while (rec != NULL) {
		if (!mail_tree_insert(tree, rec->uid,
				      INDEX_RECORD_INDEX(tree->index, rec))) {
			tree->index->header->flags |=
				MAIL_INDEX_FLAG_REBUILD_TREE;
			return FALSE;
		}

		rec = tree->index->next(tree->index, rec);
	}

	return TRUE;
}

int mail_tree_sync_file(MailTree *tree)
{
	if (!tree->modified || tree->anon_mmap)
		return TRUE;

	if (tree->mmap_base != NULL) {
		if (msync(tree->mmap_base, tree->mmap_used_length, MS_SYNC) < 0)
			return tree_set_syscall_error(tree, "msync()");
	}

	if (fsync(tree->fd) < 0)
		return tree_set_syscall_error(tree, "fsync()");

	tree->modified = FALSE;
	return TRUE;
}

int _mail_tree_grow(MailTree *tree)
{
	uoff_t new_fsize;
	void *base;

	new_fsize = (uoff_t)tree->mmap_full_length + TREE_GROW_SIZE;
	i_assert(new_fsize < OFF_T_MAX);

	if (tree->anon_mmap) {
		i_assert(new_fsize < SSIZE_T_MAX);

		base = mremap_anon(tree->mmap_base, tree->mmap_full_length,
				   (size_t)new_fsize, MREMAP_MAYMOVE);
		if (base == MAP_FAILED)
			return tree_set_syscall_error(tree, "mremap_anon()");

		tree->mmap_base = base;
		tree->mmap_full_length = (size_t)new_fsize;
		return TRUE;
	}

	if (file_set_size(tree->fd, (off_t)new_fsize) < 0) {
		if (errno == ENOSPC)
			tree->index->nodiskspace = TRUE;
		return tree_set_syscall_error(tree, "file_set_size()");
	}

	if (!mmap_update(tree, TRUE) || !mmap_verify(tree))
		return FALSE;

	return TRUE;
}
