#ifndef IMAP_REPLY_H
#define IMAP_REPLY_H

/* Reply texts sent both by the imap process and by imap-hibernate. Keeping
   them in one place makes sure that clients see the same replies regardless
   of which process answers them. */

/* Untagged and continuation replies */
#define IMAP_REPLY_IDLE_CONTINUE "+ idling"
#define IMAP_REPLY_IDLE_STILL_HERE "* OK Still here"
#define IMAP_REPLY_LOGOUT_BYE "* BYE Logging out"
#define IMAP_REPLY_BYE_INACTIVITY "* BYE Disconnected for inactivity."

/* Tagged replies (without the tag). IDLE can be finished with OK or BAD. */
#define IMAP_REPLY_IDLE_COMPLETED "Idle completed."
#define IMAP_REPLY_NOOP_COMPLETED "OK NOOP completed."
#define IMAP_REPLY_CHECK_COMPLETED "OK Check completed."
#define IMAP_REPLY_LOGOUT_COMPLETED "OK Logout completed."

#endif
