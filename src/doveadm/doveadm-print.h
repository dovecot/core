#ifndef DOVEADM_PRINT_H
#define DOVEADM_PRINT_H

#define DOVEADM_PRINT_TYPE_FLOW "flow"
#define DOVEADM_PRINT_TYPE_TABLE "table"

enum doveadm_print_header_flags {
	DOVEADM_PRINT_HEADER_FLAG_RIGHT_JUSTIFY 	= 0x01,
	DOVEADM_PRINT_HEADER_FLAG_STICKY	 	= 0x02,
	DOVEADM_PRINT_HEADER_FLAG_HIDE_TITLE	 	= 0x04
};

void doveadm_print_header(const char *key, const char *title,
			  enum doveadm_print_header_flags flags);
void doveadm_print_header_simple(const char *key_title);
void doveadm_print(const char *value);
void doveadm_print_num(uintmax_t value);
void doveadm_print_sticky(const char *key, const char *value);

void doveadm_print_init(const char *name);
void doveadm_print_deinit(void);

#endif
