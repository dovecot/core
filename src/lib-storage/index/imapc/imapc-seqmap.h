#ifndef IMAPC_SEQMAP_H
#define IMAPC_SEQMAP_H

/* Defines a mapping between remote and local sequence numbers.
   Initially they start the same, but remote sequences can be marked as
   expunged, which alters the mapping until the seqmap is reset (i.e. when the
   mailbox is synced and local sequences are expunged too).

   So for example calling imapc_seqmap_expunge(seqmap, 1) twice expunges the
   first and the second local sequence. imapc_seqmap_rseq_to_lseq(seqmap, 1)
   will afterward return 3. */

struct imapc_seqmap *imapc_seqmap_init(void);
void imapc_seqmap_deinit(struct imapc_seqmap **seqmap);

/* Reset local and remote sequences to be equal. */
void imapc_seqmap_reset(struct imapc_seqmap *seqmap);
bool imapc_seqmap_is_reset(struct imapc_seqmap *seqmap);

/* Mark given remote sequence expunged. */
void imapc_seqmap_expunge(struct imapc_seqmap *seqmap, uint32_t rseq);
/* Convert remote sequence to local sequence. */
uint32_t imapc_seqmap_rseq_to_lseq(struct imapc_seqmap *seqmap, uint32_t rseq);
/* Convert local sequence to remote sequence. */
uint32_t imapc_seqmap_lseq_to_rseq(struct imapc_seqmap *seqmap, uint32_t lseq);

#endif
