#ifndef __IMAP_SEARCH_H
#define __IMAP_SEARCH_H

/* Builds search arguments based on IMAP arguments. */
struct mail_search_arg *
imap_search_args_build(pool_t pool, struct imap_arg *args, const char **error);

struct mail_search_arg *
imap_search_get_msgset_arg(const char *messageset, int uidset);

#endif
