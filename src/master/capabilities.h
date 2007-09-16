#ifndef CAPABILITIES_H
#define CAPABILITIES_H

#if defined(HAVE_LIBCAP)

void drop_capabilities(void);

#else

static inline void drop_capabilities(void) {}

#endif

#endif
