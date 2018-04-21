#ifndef MACROS_H
#define MACROS_H

/* several useful macros, mostly from glib.h */

#ifndef NULL
#  define NULL ((void *)0)
#endif

#ifndef FALSE
#  define FALSE (!1)
#endif

#ifndef TRUE
#  define TRUE (!FALSE)
#endif

#define N_ELEMENTS(arr) \
	(sizeof(arr) / sizeof((arr)[0]))

#define MEM_ALIGN(size) \
	(((size) + MEM_ALIGN_SIZE-1) & ~((size_t) MEM_ALIGN_SIZE-1))

#define PTR_OFFSET(ptr, offset) \
	((void *) (((unsigned char *) (ptr)) + (offset)))
#define CONST_PTR_OFFSET(ptr, offset) \
	((const void *) (((const unsigned char *) (ptr)) + (offset)))

#define container_of(ptr, type, name) \
	(type *)((uintptr_t)(ptr) - (uintptr_t)offsetof(type, name) + \
		 COMPILE_ERROR_IF_TYPES_NOT_COMPATIBLE(ptr, &((type *) 0)->name))

/* Don't use simply MIN/MAX, as they're often defined elsewhere in include
   files that are included after this file generating tons of warnings. */
#define I_MIN(a, b)  (((a) < (b)) ? (a) : (b))
#define I_MAX(a, b)  (((a) > (b)) ? (a) : (b))

/* make it easier to cast from/to pointers. assumes that
   sizeof(size_t) == sizeof(void *) and they're both the largest datatypes
   that are allowed to be used. so, long long isn't safe with these. */
#define POINTER_CAST(i) \
	((void *) ((char *) NULL + (i)))
#define POINTER_CAST_TO(p, type) \
	((type) ((const char *) (p) - (const char *) NULL))

/* Define VA_COPY() to do the right thing for copying va_list variables.
   config.h may have already defined VA_COPY as va_copy or __va_copy. */
#ifndef VA_COPY
#  if defined (__GNUC__) && defined (__PPC__) && \
      (defined (_CALL_SYSV) || defined (_WIN32))
#    define VA_COPY(ap1, ap2) (*(ap1) = *(ap2))
#  elif defined (VA_COPY_AS_ARRAY)
#    define VA_COPY(ap1, ap2) memmove ((ap1), (ap2), sizeof (va_list))
#  else /* va_list is a pointer */
#    define VA_COPY(ap1, ap2) ((ap1) = (ap2))
#  endif /* va_list is a pointer */
#endif

/* Provide convenience macros for handling structure
 * fields through their offsets.
 */
#define STRUCT_MEMBER_P(struct_p, struct_offset) \
	((void *) ((char *) (struct_p) + (long) (struct_offset)))
#define CONST_STRUCT_MEMBER_P(struct_p, struct_offset) \
	((const void *) ((const char *) (struct_p) + (long) (struct_offset)))

/* Provide simple macro statement wrappers (adapted from Perl):
   STMT_START { statements; } STMT_END;
   can be used as a single statement, as in
   if (x) STMT_START { ... } STMT_END; else ...

   For gcc we will wrap the statements within `({' and `})' braces.
   For SunOS they will be wrapped within `if (1)' and `else (void) 0',
   and otherwise within `do' and `while (0)'. */
#if !(defined (STMT_START) && defined (STMT_END))
#  if defined (__GNUC__) && !defined (__cplusplus) && \
	!defined (__STRICT_ANSI__) && !defined (PEDANTIC)
#    define STMT_START (void)(
#    define STMT_END   )
#  else
#    if (defined (sun) || defined (__sun__))
#      define STMT_START if (1)
#      define STMT_END   else (void)0
#    else
#      define STMT_START do
#      define STMT_END   while (0)
#    endif
#  endif
#endif

/* Provide macros to feature the GCC function attribute. */
#if __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ > 4)
#  define ATTRS_DEFINED
#  define ATTR_FORMAT(format_idx, arg_idx) \
	__attribute__((format (printf, format_idx, arg_idx)))
#  define ATTR_FORMAT_ARG(arg_idx) \
	__attribute__((format_arg (arg_idx)))
#  define ATTR_SCANF(format_idx, arg_idx) \
	__attribute__((format (scanf, format_idx, arg_idx)))
#  define ATTR_STRFTIME(format_idx) \
	__attribute__((format (strftime, format_idx, 0)))
#  define ATTR_UNUSED __attribute__((unused))
#  define ATTR_NORETURN __attribute__((noreturn))
#  define ATTR_CONST __attribute__((const))
#  define ATTR_PURE __attribute__((pure))
#else
#  define ATTR_FORMAT(format_idx, arg_idx)
#  define ATTR_FORMAT_ARG(arg_idx)
#  define ATTR_SCANF(format_idx, arg_idx)
#  define ATTR_STRFTIME(format_idx)
#  define ATTR_UNUSED
#  define ATTR_NORETURN
#  define ATTR_CONST
#  define ATTR_PURE
#endif
#ifdef HAVE_ATTR_NULL
#  define ATTR_NULL(...) __attribute__((null(__VA_ARGS__)))
#else
#  define ATTR_NULL(...)
#endif
#ifdef HAVE_ATTR_NOWARN_UNUSED_RESULT
#  define ATTR_NOWARN_UNUSED_RESULT __attribute__((nowarn_unused_result))
#else
#  define ATTR_NOWARN_UNUSED_RESULT
#endif
#if __GNUC__ > 2
#  define ATTR_MALLOC __attribute__((malloc))
#else
#  define ATTR_MALLOC
#endif
#if __GNUC__ > 3
/* GCC 4.0 and later */
#  define ATTR_WARN_UNUSED_RESULT __attribute__((warn_unused_result))
#  define ATTR_SENTINEL __attribute__((sentinel))
#else
#  define ATTR_WARN_UNUSED_RESULT
#  define ATTR_SENTINEL
#endif
#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 3)
/* GCC 4.3 and later */
#  define ATTR_HOT __attribute__((hot))
#  define ATTR_COLD __attribute__((cold))
#else
#  define ATTR_HOT
#  define ATTR_COLD
#endif
#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 9)
/* GCC 4.9 and later */
#  define ATTR_RETURNS_NONNULL __attribute__((returns_nonnull))
#else
#  define ATTR_RETURNS_NONNULL
#endif
#ifdef HAVE_ATTR_DEPRECATED
#  define ATTR_DEPRECATED(str) __attribute__((deprecated(str)))
#else
#  define ATTR_DEPRECATED(str)
#endif

/* Macros to provide type safety for callback functions' context parameters */
#ifdef HAVE_TYPE_CHECKS
#  define CALLBACK_TYPECHECK(callback, type) \
	(COMPILE_ERROR_IF_TRUE(!__builtin_types_compatible_p( \
		typeof(&callback), type)) ? 1 : 0)
#else
#  define CALLBACK_TYPECHECK(callback, type) 0
#endif

#if (__GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ > 0)) && !defined(__cplusplus)
#  define COMPILE_ERROR_IF_TRUE(condition) \
	(sizeof(char[1 - 2 * ((condition) ? 1 : 0)]) - 1)
#else
#  define COMPILE_ERROR_IF_TRUE(condition) 0
#endif

#ifdef HAVE_TYPE_CHECKS
#  define COMPILE_ERROR_IF_TYPES_NOT_COMPATIBLE(_a, _b) \
	COMPILE_ERROR_IF_TRUE( \
		!__builtin_types_compatible_p(typeof(_a), typeof(_b)))
#define COMPILE_ERROR_IF_TYPES2_NOT_COMPATIBLE(_a1, _a2, _b) \
	COMPILE_ERROR_IF_TRUE( \
		!__builtin_types_compatible_p(typeof(_a1), typeof(_b)) && \
		!__builtin_types_compatible_p(typeof(_a2), typeof(_b)))
#else
#  define COMPILE_ERROR_IF_TYPES_NOT_COMPATIBLE(_a, _b) 0
#  define COMPILE_ERROR_IF_TYPES2_NOT_COMPATIBLE(_a1, _a2, _b) 0
#endif

#if __GNUC__ > 2
#  define unlikely(expr) (__builtin_expect((expr) ? 1 : 0, 0) != 0)
#  define likely(expr) (__builtin_expect((expr) ? 1 : 0, 1) != 0)
#else
#  define unlikely(expr) expr
#  define likely(expr) expr
#endif

#if defined(__clang__) && ((__clang_major__ > 4) || (__clang_major__ == 3 && __clang_minor__ >= 9))
#  define ATTR_UNSIGNED_WRAPS __attribute__((no_sanitize("integer")))
#else
#  define ATTR_UNSIGNED_WRAPS
#endif

/* Provide macros for error handling. */
#ifdef DISABLE_ASSERTS
#  define i_assert(expr)
#else

#define i_assert(expr)			STMT_START{			\
     if (unlikely(!(expr)))						\
       i_panic("file %s: line %d (%s): assertion failed: (%s)",		\
		__FILE__,						\
		__LINE__,						\
		__func__,					\
		#expr);			}STMT_END

#endif

#ifndef STATIC_CHECKER
#  define i_unreached() \
	i_panic("file %s: line %d: unreached", __FILE__, __LINE__)
#else
#  define i_unreached() __builtin_unreachable()
#endif

/* Convenience macros to test the versions of dovecot. */
#if defined DOVECOT_VERSION_MAJOR && defined DOVECOT_VERSION_MINOR
#  define DOVECOT_PREREQ(maj, min) \
          ((DOVECOT_VERSION_MAJOR << 16) + DOVECOT_VERSION_MINOR >= ((maj) << 16) + (min))
#else
#  define DOVECOT_PREREQ(maj, min) 0
#endif

#ifdef __cplusplus
#  undef STATIC_ARRAY
#  define STATIC_ARRAY
#endif

/* Convenience wrappers for initializing a struct */
#define i_zero(p) memset(p, 0, sizeof(*(p)))
#define i_zero_safe(p) safe_memset(p, 0, sizeof(*(p)))

#define ST_CHANGED(st_a, st_b) \
	((st_a).st_mtime != (st_b).st_mtime || \
	 ST_MTIME_NSEC(st_a) != ST_MTIME_NSEC(st_b) || \
	 (st_a).st_size != (st_b).st_size || \
	 (st_a).st_ino != (st_b).st_ino)

#endif
