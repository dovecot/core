#ifndef __MAIL_TREE_H
#define __MAIL_TREE_H

struct mail_tree {
	struct mail_index *index;

	int fd;
	char *filepath;

	void *mmap_base;
	struct mail_tree_node *node_base;
	size_t mmap_used_length;
	size_t mmap_full_length;
	size_t mmap_highwater; /* for msync()ing */

        struct mail_tree_header *header;
	unsigned int sync_id;

	unsigned int anon_mmap:1;
	unsigned int modified:1;
};

struct mail_tree_header {
	unsigned int indexid;
	unsigned int sync_id;

	uoff_t used_file_size;

	unsigned int root;
};

struct mail_tree_node {
	unsigned int left;
	unsigned int right;
	unsigned int up;

	/* number of child nodes + 1, used to figure out message
	   sequence numbers. also highest bit specifies if the node is
	   red or black */
	unsigned int node_count;

	unsigned int key;
	unsigned int value;
};

int mail_tree_create(struct mail_index *index);
int mail_tree_open_or_create(struct mail_index *index);
void mail_tree_free(struct mail_tree *tree);

int mail_tree_reset(struct mail_tree *tree);
int mail_tree_rebuild(struct mail_tree *tree);
int mail_tree_sync_file(struct mail_tree *tree, int *fsync_fd);

/* Find first existing UID in range. Returns (unsigned int)-1 if not found. */
unsigned int mail_tree_lookup_uid_range(struct mail_tree *tree,
					unsigned int *seq_r,
					unsigned int first_uid,
					unsigned int last_uid);

/* Find message by sequence number. Returns (unsigned int)-1 if not found. */
unsigned int mail_tree_lookup_sequence(struct mail_tree *tree,
				       unsigned int seq);

/* Insert a new record in tree. */
int mail_tree_insert(struct mail_tree *tree,
		     unsigned int uid, unsigned int index);

/* Update existing record in tree. */
int mail_tree_update(struct mail_tree *tree,
		     unsigned int uid, unsigned int index);

/* Delete record from tree. */
void mail_tree_delete(struct mail_tree *tree, unsigned int uid);

/* private: */
int _mail_tree_set_corrupted(struct mail_tree *tree, const char *fmt, ...)
	__attr_format__(2, 3);
int _mail_tree_mmap_update(struct mail_tree *tree, int forced);
int _mail_tree_grow(struct mail_tree *tree);
void _mail_tree_truncate(struct mail_tree *tree);

#endif
