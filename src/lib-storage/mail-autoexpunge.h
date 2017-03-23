#ifndef MAIL_AUTOEXPUNGE_H
#define MAIL_AUTOEXPUNGE_H

/* Perform autoexpunging for all the user's mailboxes that have autoexpunging
   configured. Returns number of mails that were autoexpunged. */
unsigned int mail_user_autoexpunge(struct mail_user *user);

#endif
