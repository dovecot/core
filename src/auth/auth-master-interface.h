#ifndef __AUTH_MASTER_INTERFACE_H
#define __AUTH_MASTER_INTERFACE_H

#define AUTH_MASTER_MAX_REPLY_DATA_SIZE 4096

struct auth_master_request {
	unsigned int tag;

	unsigned int id;
	unsigned int login_pid;
};

struct auth_master_reply {
	unsigned int tag;

	unsigned int success:1;

	uid_t uid;
	gid_t gid;

	/* variable width fields are packed into data[]. These variables
	   contain indexes to the data, they're all NUL-terminated.
	   Ignore if it points outside data_size. */
	size_t system_user_idx;
	size_t virtual_user_idx;
	size_t home_idx, mail_idx, chroot_idx;

	size_t data_size;
	/* unsigned char data[]; */
};

#endif
