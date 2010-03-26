#ifndef MACROS_H
#define MACROS_H

/* several useful macros, mostly from glib.h */

#ifndef NULL
#  define NULL ((void *)0)
#endif

#ifndef FALSE
#  define FALSE (0)
#endif

#ifndef TRUE
#  define TRUE (!FALSE)
#endif

#define N_ELEMENTS(arr) \
	(sizeof(arr) / sizeof((arr)[0]))

#define BITS_IN_UINT (CHAR_BIT * sizeof(unsigned int))
#define BITS_IN_SIZE_T (CHAR_BIT * sizeof(size_t))

#define MEM_ALIGN(size) \
	(((size) + MEM_ALIGN_SIZE-1) & ~((unsigned int) MEM_ALIGN_SIZE-1))

#define PTR_OFFSET(ptr, offset) \
	((void *) (((unsigned char *) (ptr)) + (offset)))
#define CONST_PTR_OFFSET(ptr, offset) \
	((const void *) (((const unsigned char *) (ptr)) + (offset)))

/* Don't use simply MIN/MAX, as they're often defined elsewhere in include
   files that are included after this file generating tons of warnings. */
#define I_MIN(a, b)  (((a) < (b)) ? (a) : (b))
#define I_MAX(a, b)  (((a) > (b)) ? (a) : (b))

#undef CLAMP
#define CLAMP(x, low, high) \
	(((x) > (high)) ? (high) : (((x) < (low)) ? (low) : (x)))

#undef NVL
#define NVL(str, nullstr) ((str) != NULL ? (str) : (nullstr))

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
#  define ATTR_UNUSED __attribute__((unused))
#  define ATTR_NORETURN __attribute__((noreturn))
#  define ATTR_CONST __attribute__((const))
#  define ATTR_PURE __attribute__((pure))
#else
#  define ATTR_FORMAT(format_idx, arg_idx)
#  define ATTR_FORMAT_ARG(arg_idx)
#  define ATTR_SCANF
#  define ATTR_UNUSED
#  define ATTR_NORETURN
#  define ATTR_CONST
#  define ATTR_PURE
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

/* Macros to provide type safety for callback functions' context parameters */
#ifdef __GNUC__
#  define CONTEXT_TYPE_SAFETY
#endif
#ifdef CONTEXT_TYPE_SAFETY
#  define CONTEXT_CALLBACK(name, callback_type, callback, context, ...) \
	({(void)(1 ? 0 : callback(context)); \
	name(__VA_ARGS__, (callback_type *)callback, context); })
#  define CONTEXT_CALLBACK2(name, callback_type, callback, arg1_type, context, ...) \
	({(void)(1 ? 0 : callback((arg1_type)0, context)); \
	name(__VA_ARGS__, (callback_type *)callback, context); })
#else
#  define CONTEXT_CALLBACK(name, callback_type, callback, context, ...) \
	name(__VA_ARGS__, (callback_type *)callback, context)
#  define CONTEXT_CALLBACK2(name, callback_type, callback, arg1_type, context, ...) \
	name(__VA_ARGS__, (callback_type *)callback, context)
#endif

#if __GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ > 0)
#  define HAVE_TYPEOF
#  define COMPILE_ERROR_IF_TRUE(condition) \
	(sizeof(char[1 - 2 * !!(condition)]) - 1)
#  define COMPILE_ERROR_IF_TYPES_NOT_COMPATIBLE(_a, _b) \
	COMPILE_ERROR_IF_TRUE( \
		!__builtin_types_compatible_p(typeof(_a), typeof(_b)))
#else
#  define COMPILE_ERROR_IF_TRUE(condition) 0
#  define COMPILE_ERROR_IF_TYPES_NOT_COMPATIBLE(_a, _b) 0
#endif

#if __GNUC__ > 2
#  define unlikely(expr) __builtin_expect(!!(expr), 0)
#  define likely(expr) __builtin_expect(!!(expr), 1)
#else
#  define unlikely(expr) expr
#  define likely(expr) expr
#endif

/* Provide macros for error handling. */
#ifdef DISABLE_ASSERTS
#  define i_assert(expr)
#elif defined (__GNUC__) && !defined (__STRICT_ANSI__)

#define i_assert(expr)			STMT_START{			\
     if (unlikely(!(expr)))						\
       i_panic("file %s: line %d (%s): assertion failed: (%s)",		\
		__FILE__,						\
		__LINE__,						\
		__FUNCTION__,					\
		#expr);			}STMT_END

#else /* !__GNUC__ */

#define i_assert(expr)			STMT_START{		\
     if (unlikely(!(expr)))					\
       i_panic("file %s: line %d: assertion failed: (%s)",	\
	      __FILE__,						\
	      __LINE__,						\
	      #expr);			}STMT_END

#endif

#define i_unreached() \
	i_panic("file %s: line %d: unreached", __FILE__, __LINE__)

#endif
