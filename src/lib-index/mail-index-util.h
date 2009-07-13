#ifndef MAIL_INDEX_UTIL_H
#define MAIL_INDEX_UTIL_H

ARRAY_DEFINE_TYPE(seq_array, uint32_t);

uint32_t mail_index_uint32_to_offset(uint32_t offset);
uint32_t mail_index_offset_to_uint32(uint32_t offset);

#define MAIL_INDEX_PACK_MAX_SIZE ((sizeof(uint32_t) * 8 + 7) / 7)
void mail_index_pack_num(uint8_t **p, uint32_t num);
int mail_index_unpack_num(const uint8_t **p, const uint8_t *end,
			  uint32_t *num_r);

bool mail_index_seq_array_lookup(const ARRAY_TYPE(seq_array) *array,
				 uint32_t seq, unsigned int *idx_r);
bool mail_index_seq_array_add(ARRAY_TYPE(seq_array) *array, uint32_t seq,
			      const void *record, size_t record_size,
			      void *old_record);

#endif
