#ifndef __MAIL_LOCKDIR_H
#define __MAIL_LOCKDIR_H

/* Exclusively lock whole directory where index is located. */
int mail_index_lock_dir(MailIndex *index, MailLockType lock_type);

#endif
