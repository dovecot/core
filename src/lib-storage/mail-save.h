#ifndef __MAIL_SAVE_H
#define __MAIL_SAVE_H

typedef int write_func_t(struct ostream *, const void *, size_t);

/* Return -1 = failure, 0 = don't write the header, 1 = write it */
typedef int header_callback_t(const char *name,
			      write_func_t *write_func, void *context);

int mail_storage_save(struct mail_storage *storage, const char *path,
		      struct istream *input, struct ostream *output, int crlf,
		      header_callback_t *header_callback, void *context);

#endif
