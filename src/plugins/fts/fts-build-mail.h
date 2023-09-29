#ifndef FTS_BUILD_MAIL_H
#define FTS_BUILD_MAIL_H

/* Build indexes for the given mail.
   Returns -1 on error, The error is set to mail's storage.
   Returns  0 on ignored error (retry limit reached and mail not built,
                                see comments in function implementation)
   Returns  1 on success */
int fts_build_mail(struct fts_backend_update_context *update_ctx,
		   struct mail *mail);

#endif
