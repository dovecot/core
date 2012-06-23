#ifndef SMTP_CLIENT_H
#define SMTP_CLIENT_H

#include <stdio.h>

struct smtp_client * ATTR_NULL(3)
smtp_client_open(const struct lda_settings *set, const char *destination,
		 const char *return_path, struct ostream **output_r);
/* Returns sysexits-compatible return value */
int smtp_client_close(struct smtp_client *client);

#endif
