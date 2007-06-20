#ifndef __CAPABILITIES_H__
#define __CAPABILITIES_H__

#if defined(HAVE_LIBCAP)

void drop_capabilities(void);

#else

static inline void drop_capabilities(void) {}

#endif

#endif	/* __CAPABILITIES_H__ */
