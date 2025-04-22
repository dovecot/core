#ifndef UNICODE_DATA_H
#define UNICODE_DATA_H

#include "unicode-data-tables.h"

static inline bool
unicode_general_category_is_group(enum unicode_general_category gencat)
{
	return ((gencat & 0x0f) == 0x00);
}

static inline const struct unicode_code_point_data *
unicode_code_point_get_data(uint32_t cp)
{
	unsigned int idx8 = cp >> 24;
	unsigned int blk16 = unicode_code_points_index8[idx8];
	unsigned int idx16 = (blk16 << 8) + ((cp >> 16) & 0xFF);
	unsigned int blk24 = unicode_code_points_index16[idx16];
	unsigned int idx24 = (blk24 << 8) + ((cp >> 8) & 0xFF);
	unsigned int blk32 = unicode_code_points_index24[idx24];
	unsigned int idx32 = (blk32 << 8) + (cp & 0xFF);
	unsigned int idxcp = unicode_code_points_index32[idx32];

	return &unicode_code_points[idxcp];
}

static inline size_t
unicode_code_point_data_get_first_decomposition(
	const struct unicode_code_point_data *cp_data,
	uint8_t *type_r, const uint32_t **decomp_r)
{
	uint32_t offset;

	if (type_r != NULL)
		*type_r = cp_data->decomposition_type;
	offset = cp_data->decomposition_first_offset;
	*decomp_r = &unicode_decompositions[offset];
	return cp_data->decomposition_first_length;
}

static inline size_t
unicode_code_point_data_get_full_decomposition(
	const struct unicode_code_point_data *cp_data, bool canonical,
	const uint32_t **decomp_r)
{
	uint32_t offset;

	if (canonical) {
		offset = cp_data->decomposition_full_offset;
		*decomp_r = &unicode_decompositions[offset];
		return cp_data->decomposition_full_length;
	}
	offset = cp_data->decomposition_full_k_offset;
	*decomp_r = &unicode_decompositions[offset];
	return cp_data->decomposition_full_k_length;
}

static inline uint32_t
unicode_code_point_data_find_composition(
	const struct unicode_code_point_data *cp_data, uint32_t second)
{
	const uint32_t *compositions =
		&unicode_compositions[cp_data->composition_offset];
	size_t left_idx, right_idx;

	left_idx = 0; right_idx = cp_data->composition_count;
	while (left_idx < right_idx) {
		unsigned int idx = (left_idx + right_idx) / 2;

		if (second > compositions[idx])
			left_idx = idx + 1;
		else if (second < compositions[idx])
			right_idx = idx;
		else {
			return unicode_composition_primaries[
				cp_data->composition_offset + idx];
		}
	}

	return 0x0000;
}

static inline size_t
unicode_code_point_get_full_decomposition(uint32_t cp, bool canonical,
					  const uint32_t **decomp_r)
{
	const struct unicode_code_point_data *cp_data =
		unicode_code_point_get_data(cp);

	return unicode_code_point_data_get_full_decomposition(
		cp_data, canonical, decomp_r);
}

uint8_t unicode_general_category_from_string(const char *str);

#endif
