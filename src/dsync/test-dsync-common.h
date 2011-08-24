#ifndef TEST_DSYNC_COMMON_H
#define TEST_DSYNC_COMMON_H

#include "test-common.h"
#include "dsync-data.h"

#define TEST_MAILBOX_GUID1 "1234456789abcdef2143547698badcfe"
#define TEST_MAILBOX_GUID2 "a3bd7824defe08f7acc7ca8ce739dbca"

extern const guid_128_t test_mailbox_guid1;
extern const guid_128_t test_mailbox_guid2;

bool dsync_messages_equal(const struct dsync_message *m1,
			  const struct dsync_message *m2);
bool dsync_mailboxes_equal(const struct dsync_mailbox *box1,
			   const struct dsync_mailbox *box2);

#endif
