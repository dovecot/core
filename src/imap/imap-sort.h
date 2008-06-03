#ifndef IMAP_SORT_H
#define IMAP_SORT_H

int imap_sort(struct client_command_context *cmd, struct mail_search_args *args,
	      const enum mail_sort_type *sort_program);

#endif
