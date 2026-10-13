#ifndef MAIL_AUTOEXPUNGE_H
#define MAIL_AUTOEXPUNGE_H

/* Maximum interval for the next autoexpunge check returned by
   mail_user_autoexpunge() */
#define MAIL_AUTOEXPUNGE_CHECK_MAX_INTERVAL_SECS (24*60*60)

/* Perform autoexpunging for all the user's mailboxes that have autoexpunging
   configured. Returns number of mails that were autoexpunged.

   If next_check_r is non-NULL, it's set to the time when autoexpunging
   should be checked again. This is the earliest time when a mail in a
   mailbox with autoexpunge setting is known to expire, but at most the
   smallest autoexpunge setting value or
   MAIL_AUTOEXPUNGE_CHECK_MAX_INTERVAL_SECS. It's set to 0 if not
   all mailboxes could be checked because another process was
   autoexpunging the user, i.e. the check should be retried soon. */
unsigned int mail_user_autoexpunge(struct mail_user *user,
				   time_t *next_check_r);

#endif
