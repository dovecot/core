#ifndef IMAPC_MSGMAP_H
#define IMAPC_MSGMAP_H

struct imapc_msgmap *imapc_msgmap_init(void);
void imapc_msgmap_deinit(struct imapc_msgmap **msgmap);

uint32_t imapc_msgmap_count(struct imapc_msgmap *msgmap);
uint32_t imapc_msgmap_uidnext(struct imapc_msgmap *msgmap);
uint32_t imapc_msgmap_rseq_to_uid(struct imapc_msgmap *msgmap, uint32_t rseq);
bool imapc_msgmap_uid_to_rseq(struct imapc_msgmap *msgmap,
			      uint32_t uid, uint32_t *rseq_r);

void imapc_msgmap_append(struct imapc_msgmap *msgmap,
			 uint32_t rseq, uint32_t uid);
void imapc_msgmap_expunge(struct imapc_msgmap *msgmap, uint32_t rseq);
void imapc_msgmap_reset(struct imapc_msgmap *msgmap);

#endif
