#ifndef IMAP_SORT_H
#define IMAP_SORT_H

int imap_sort(struct client_command_context *cmd, const char *charset,
	      struct mail_search_arg *args,
	      const enum mail_sort_type *sort_program);

#endif
