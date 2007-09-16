#ifndef SQUAT_TRIE_PRIVATE_H
#define SQUAT_TRIE_PRIVATE_H

struct squat_trie_header {
	uint8_t version;
	uint8_t unused[3];

	uint32_t uidvalidity;
	uint32_t used_file_size;
	uint32_t deleted_space;
	uint32_t node_count;
	uint32_t modify_counter;

	uint32_t root_offset;
};

/*
packed_node {
	packed ((8bit_chars_count << 1) | have_16bit_chars);
	uint8_t 8bit_chars[8bit_chars_count];
	uint32_t idx[8bit_chars_count];
	if (have_16bit_chars) {
		packed 16bit_chars_count;
		uint16_t 16bit_chars[16bit_chars_count];
		uint32_t idx[16bit_chars_count];
	}
}
*/

#endif
