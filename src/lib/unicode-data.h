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

uint8_t unicode_general_category_from_string(const char *str);

#endif
