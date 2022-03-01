#ifndef FTS_BUILD_MAIL_H
#define FTS_BUILD_MAIL_H

/* Build indexes for the given mail. Returns 0 on success, -1 on error.
   The error is set to mail's storage. */
int fts_build_mail(struct fts_backend_update_context *update_ctx,
		   struct mail *mail);

#endif
