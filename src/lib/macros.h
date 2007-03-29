#ifndef __MACROS_H
#define __MACROS_H

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
#define STRUCT_MEMBER(member_type, struct_p, struct_offset) \
	(*(member_type *) G_STRUCT_MEMBER_P((struct_p), (struct_offset)))

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
#  define __attrs_used__
#  define __attr_format__(format_idx, arg_idx) \
	__attribute__((format (printf, format_idx, arg_idx)))
#  define __attr_format_arg__(arg_idx) \
	__attribute__((format_arg (arg_idx)))
#  define __attr_scanf__(format_idx, arg_idx) \
	__attribute__((format (scanf, format_idx, arg_idx)))
#  define __attr_unused__ __attribute__((unused))
#  define __attr_noreturn__ __attribute__((noreturn))
#  define __attr_const__ __attribute__((const))
#  define __attr_malloc__ __attribute__((malloc))
#  if __GNUC__ > 3
/* GCC 4.0 and later */
#    define __attr_warn_unused_result__ __attribute__((warn_unused_result))
#    define __attr_sentinel__ __attribute__((sentinel))
#  else
#    define __attr_warn_unused_result__
#    define __attr_sentinel__
#  endif
#else
#  define __attr_format__(format_idx, arg_idx)
#  define __attr_format_arg__(arg_idx)
#  define __attr_unused__
#  define __attr_noreturn__
#  define __attr_const__
#  define __attr_unused__
#  define __attr_sentinel__
#endif

/* C99-style struct member definitions */
#if (defined(__STDC__) && __STDC_VERSION__ >= 199901L) || __GNUC__ > 2
#  define MEMBER(name) .name =
#else
#  define MEMBER(name)
#endif

/* Macros to provide type safety for callback functions' context parameters */
#ifdef __GNUC__
#  define CONTEXT_TYPE_SAFETY
#endif
#ifdef CONTEXT_TYPE_SAFETY
#  define CONTEXT_CALLBACK(name, callback_type, callback, context, ...) \
	({(void)(1 ? 0 : callback(context)); \
	name(__VA_ARGS__, (callback_type *)callback, context); })
#else
#  define CONTEXT_CALLBACK(name, callback_type, callback, context, ...) \
	name(__VA_ARGS__, (callback_type *)callback, context)
#endif

#ifdef __GNUC__
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

/* Wrap the gcc __PRETTY_FUNCTION__ and __FUNCTION__ variables with
   macros, so we can refer to them as strings unconditionally. */
#ifdef __GNUC__
#  define GNUC_FUNCTION __FUNCTION__
#  define GNUC_PRETTY_FUNCTION __PRETTY_FUNCTION__
#else
#  define GNUC_FUNCTION ""
#  define GNUC_PRETTY_FUNCTION ""
#endif

/* Provide macros for error handling. */
#ifdef DISABLE_ASSERTS
#  define i_assert(expr)
#elif defined (__GNUC__) && !defined (__STRICT_ANSI__)

#define i_assert(expr)			STMT_START{			\
     if (!(expr))							\
       i_panic("file %s: line %d (%s): assertion failed: (%s)",		\
		__FILE__,							\
		__LINE__,							\
		__PRETTY_FUNCTION__,					\
		#expr);			}STMT_END

#else /* !__GNUC__ */

#define i_assert(expr)			STMT_START{		\
     if (!(expr))						\
       i_panic("file %s: line %d: assertion failed: (%s)",	\
	      __FILE__,						\
	      __LINE__,						\
	      #expr);			}STMT_END

#endif

#define i_unreached() \
	i_panic("file %s: line %d: unreached", __FILE__, __LINE__)

#endif
