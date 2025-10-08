#ifndef MAILDIR_MAIL_H
#define MAILDIR_MAIL_H

#include "index-mail.h"

struct maildir_mail {
	struct index_mail imail;
	enum mail_fetch_field corrupted_field;
};

#endif
