#ifndef __DBOX_KEYWORDS_H
#define __DBOX_KEYWORDS_H

struct seq_range;

/* Read keywords from file into memory. Returns 1 if ok, 0 if the list is
   broken or -1 if I/O error. */
int dbox_file_read_keywords(struct dbox_mailbox *mbox, struct dbox_file *file);
/* Index file -> dbox file keyword index lookup. Returns TRUE if found. */
bool dbox_file_lookup_keyword(struct dbox_mailbox *mbox, struct dbox_file *file,
			      unsigned int index_idx, unsigned int *idx_r);
/* Save keywords to dbox file. Returns -1 if error, 0 if ok. */
int dbox_file_append_keywords(struct dbox_mailbox *mbox, struct dbox_file *file,
			      const struct seq_range *idx_range,
			      unsigned int count);

#endif
