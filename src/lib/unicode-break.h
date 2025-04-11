#ifndef UNICODE_BREAK_H
#define UNICODE_BREAK_H

struct unicode_code_point_data;

/*
 * Grapheme Cluster Boundaries (Unicode Standard Annex #29, Section 3)
 */

struct unicode_gc_break {
	unsigned int gb9c;
	unsigned int gb11;
	bool gb1:1;
	bool gb3:1;
	bool gb4:1;
	bool gb6:1;
	bool gb7:1;
	bool gb8:1;
	bool gb9b:1;
	bool gb12:1;
};

void unicode_gc_break_init(struct unicode_gc_break *gcbrk);

/* Returns TRUE if a grapheme boundary exists before the codepoint provided in
   cp. Any code point data for cp that was looked up earlier can be provided in
   the _cp_data pointer, or if it was NULL it can be retrieved there after the
   call.
 */
bool unicode_gc_break_cp(struct unicode_gc_break *gcbrk, uint32_t cp,
			 const struct unicode_code_point_data **_cp_data);

#endif
