#ifndef MAILBOX_ATTRIBUTE_INTERNAL_H
#define MAILBOX_ATTRIBUTE_INTERNAL_H

/* RFC 5464, Section 3.2.1.2: Mailbox entries */
#define MAILBOX_ATTRIBUTE_COMMENT "comment"
/* RFC 6154, Section 4: IMAP METADATA Entry for Special-Use Attributes */
#define MAILBOX_ATTRIBUTE_SPECIALUSE "specialuse"
/* RFC 5464, Section 3.2.1.1: Server entries */
#define MAIL_SERVER_ATTRIBUTE_COMMENT "comment"
#define MAIL_SERVER_ATTRIBUTE_ADMIN "admin"

void mailbox_attributes_internal_init(void);

#endif
