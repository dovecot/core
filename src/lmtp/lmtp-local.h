#ifndef LMTP_LOCAL_H
#define LMTP_LOCAL_H

struct mail_recipient;

void client_rcpt_anvil_disconnect(const struct mail_recipient *rcpt);

#endif
