#ifndef __DBOX_FILE_H
#define __DBOX_FILE_H

struct mail_index_view;
struct dbox_mailbox;
struct dbox_file;
struct dbox_file_header;

/* Returns -1 = error, 0 = expunged, 1 = ok */
int dbox_file_lookup_offset(struct dbox_mailbox *mbox,
			    struct mail_index_view *view, uint32_t seq,
			    uint32_t *file_seq_r, uoff_t *offset_r);

void dbox_file_close(struct dbox_file *file);
/* Returns -1 = error, 0 = EOF (mail was just moved / file broken), 1 = ok */
int dbox_file_seek(struct dbox_mailbox *mbox, uint32_t file_seq, uoff_t offset);
int dbox_file_seek_next_nonexpunged(struct dbox_mailbox *mbox);

void dbox_file_header_init(struct dbox_file_header *hdr);
int dbox_file_read_header(struct dbox_mailbox *mbox, struct dbox_file *file);

#endif
