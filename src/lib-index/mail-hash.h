#ifndef __MAIL_HASH_H
#define __MAIL_HASH_H

typedef struct _MailHashHeader MailHashHeader;
typedef struct _MailHashRecord MailHashRecord;

struct _MailHashHeader {
	unsigned int indexid;
	unsigned int sync_id;
	unsigned int used_records;

	unsigned int alignment;
};

struct _MailHashRecord {
	unsigned int uid;
	uoff_t position;
};

/* Open or create a hash file for index. If the hash needs to be created,
   it's also immediately built from the given index. */
int mail_hash_create(MailIndex *index);
int mail_hash_open_or_create(MailIndex *index);

void mail_hash_free(MailHash *hash);

/* Synchronize the hash file with memory map */
int mail_hash_sync_file(MailHash *hash);

/* Rebuild hash from index and reset the FLAG_REBUILD_HASH in header.
   The index must have an exclusive lock before this function is called. */
int mail_hash_rebuild(MailHash *hash);

/* Returns position in index file to given UID, or 0 if not found. */
uoff_t mail_hash_lookup_uid(MailHash *hash, unsigned int uid);

/* Update hash file. If pos is 0, the record is deleted. This call may
   rebuild the hash if it's too full. */
void mail_hash_update(MailHash *hash, unsigned int uid, uoff_t pos);

#endif
