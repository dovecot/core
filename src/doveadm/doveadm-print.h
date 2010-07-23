#ifndef DOVEADM_PRINT_H
#define DOVEADM_PRINT_H

#define DOVEADM_PRINT_TYPE_FLOW "flow"
#define DOVEADM_PRINT_TYPE_TABLE "table"

enum doveadm_print_header_flags {
	DOVEADM_PRINT_HEADER_FLAG_RIGHT_JUSTIFY 	= 0x01,
	DOVEADM_PRINT_HEADER_FLAG_STICKY	 	= 0x02,
	DOVEADM_PRINT_HEADER_FLAG_HIDE_TITLE	 	= 0x04
};

extern const struct doveadm_print_vfuncs *doveadm_print_vfuncs_all[];

bool doveadm_print_is_initialized(void);

void doveadm_print_header(const char *key, const char *title,
			  enum doveadm_print_header_flags flags);
void doveadm_print_header_simple(const char *key_title);
void doveadm_print(const char *value);
void doveadm_print_num(uintmax_t value);
/* Stream for same field continues until len=0 */
void doveadm_print_stream(const void *value, size_t size);
void doveadm_print_sticky(const char *key, const char *value);
void doveadm_print_flush(void);
void doveadm_print_unstick_headers(void);

void doveadm_print_init(const char *name);
void doveadm_print_deinit(void);

#endif
