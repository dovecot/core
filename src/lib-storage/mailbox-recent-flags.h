#ifndef MAILBOX_RECENT_FLAGS
#define MAILBOX_RECENT_FLAGS

struct mailbox;
struct mail_index_view;

void mailbox_recent_flags_set_uid(struct mailbox *box, uint32_t uid);
void mailbox_recent_flags_set_uid_forced(struct mailbox *box, uint32_t uid);
void mailbox_recent_flags_set_seqs(struct mailbox *box,
				   struct mail_index_view *view,
				   uint32_t seq1, uint32_t seq2);
bool mailbox_recent_flags_have_uid(struct mailbox *box, uint32_t uid);
void mailbox_recent_flags_reset(struct mailbox *box);
unsigned int mailbox_recent_flags_count(struct mailbox *box);
void mailbox_recent_flags_expunge_seqs(struct mailbox *box,
				       uint32_t seq1, uint32_t seq2);
void mailbox_recent_flags_expunge_uid(struct mailbox *box, uint32_t uid);

#endif
