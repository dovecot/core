#ifndef MAILBOX_LIST_INDEX_PRIVATE_H
#define MAILBOX_LIST_INDEX_PRIVATE_H

#include "file-dotlock.h"
#include "mailbox-list-index.h"

#define MAILBOX_LIST_INDEX_MAJOR_VERSION 1
#define MAILBOX_LIST_INDEX_MINOR_VERSION 0

#define MAILBOX_LIST_COMPRESS_PERCENTAGE 10
#define MAILBOX_LIST_COMPRESS_MIN_SIZE 1024

#define MAILBOX_LIST_INDEX_MMAP_MIN_SIZE (1024*32)

struct mailbox_list_index_header {
	uint8_t major_version;
	uint8_t minor_version;
	uint8_t unused[2];

	uint32_t file_seq;
	uint32_t header_size;
	uint32_t uid_validity;

	/* locking required to access the fields below: */
	uint32_t next_uid;

	uint32_t used_space;
	uint32_t deleted_space;
};

struct mailbox_list_dir_record {
	/* If non-zero, contains a pointer to updated directory list.
	   Stored using mail_index_uint32_to_offset(). */
	uint32_t next_offset;
	/* Bytes required to be able to fully read this directory's records.
	   This includes also bytes used by mailbox names that follow the
	   records (but doesn't include bytes for mailbox names that point
	   to earlier offsets in the file). */
	uint32_t dir_size;

	uint32_t count;
	/* The records are sorted 1) by their name_hash, 2) the actual name */
	/* struct mailbox_list_record records[count]; */
};

struct mailbox_list_record {
	/* CRC32 hash of the name */
	uint32_t name_hash;
	unsigned int uid:31;
	/* Set when this record has been marked as deleted. It will be removed
	   permanently the next time a new record is added to this directory
	   or on the next index compression. */
	unsigned int deleted:1;

	/* Points to a NUL-terminated record name */
	uint32_t name_offset;
	/* Pointer to child mailboxes or 0 if there are no children.
	   The offset is stored using mail_index_uint32_to_offset()
	   since it may change while we're reading */
	uint32_t dir_offset;
};

struct mailbox_list_index {
	char *filepath;
	char separator;
	struct mail_index *mail_index;
	struct file_cache *file_cache;
	struct dotlock_settings dotlock_set;

	int fd;

	void *mmap_base;
	const void *const_mmap_base;
	size_t mmap_size;
	const struct mailbox_list_index_header *hdr;

	unsigned int mmap_disable:1;
};

#define MAILBOX_LIST_RECORDS(dir) \
	((const struct mailbox_list_record *)(dir + 1))
#define MAILBOX_LIST_RECORDS_MODIFIABLE(dir) \
	((struct mailbox_list_record *)(dir + 1))
#define MAILBOX_LIST_RECORD_IDX(dir, rec) \
	((rec) - MAILBOX_LIST_RECORDS(dir))

int mailbox_list_index_set_syscall_error(struct mailbox_list_index *index,
					 const char *function);

int mailbox_list_index_dir_lookup_rec(struct mailbox_list_index *index,
				      const struct mailbox_list_dir_record *dir,
				      const char *name,
				      const struct mailbox_list_record **rec_r);
int mailbox_list_index_get_dir(struct mailbox_list_index_view *view,
			       uint32_t *offset,
			       const struct mailbox_list_dir_record **dir_r);
int mailbox_list_index_map(struct mailbox_list_index *index);

int mailbox_list_index_file_create(struct mailbox_list_index *index,
				   uint32_t uid_validity);
void mailbox_list_index_file_close(struct mailbox_list_index *index);

int mailbox_list_index_refresh(struct mailbox_list_index *index);

int mailbox_list_index_set_corrupted(struct mailbox_list_index *index,
				     const char *str);

#endif
