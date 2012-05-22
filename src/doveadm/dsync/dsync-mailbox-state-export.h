#ifndef DSYNC_MAILBOX_STATE_EXPORT_H
#define DSYNC_MAILBOX_STATE_EXPORT_H

struct dsync_mailbox_state_export *
dsync_mailbox_state_export_init(struct mailbox *box);
void dsync_mailbox_state_export_deinit(struct dsync_mailbox_state_export **exporter);

void dsync_mailbox_state_export_more(struct dsync_mailbox_state_export **exporter);

// vai

int dsync_mailbox_state_export(struct mailbox *box, struct ostream *output);

#endif
