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

#define MEM_ALIGN(size) \
	(((size) + MEM_ALIGN_SIZE-1) & ~((unsigned int) MEM_ALIGN_SIZE-1))

/* Don't use simply MIN/MAX, as they're often defined elsewhere in include
   files that are included after this file generating tons of warnings. */
#define I_MIN(a, b)  (((a) < (b)) ? (a) : (b))
#define I_MAX(a, b)  (((a) > (b)) ? (a) : (b))

#undef CLAMP
#define CLAMP(x, low, high)  (((x) > (high)) ? (high) : (((x) < (low)) ? (low) : (x)))

#undef NVL
#define NVL(str, nullstr) ((str) != NULL ? (str) : (nullstr))

#define POINTER_TO_INT(p)	((int) (p))
#define POINTER_TO_UINT(p)	((unsigned int) (p))

#define INT_TO_POINTER(i)	((void *) (i))
#define UINT_TO_POINTER(u)	((void *) (u))

/* Define VA_COPY() to do the right thing for copying va_list variables. */
#ifndef VA_COPY
#  if defined (__GNUC__) && defined (__PPC__) && (defined (_CALL_SYSV) || defined (_WIN32))
#    define VA_COPY(ap1, ap2) (*(ap1) = *(ap2))
#  elif defined (VA_COPY_AS_ARRAY)
#    define VA_COPY(ap1, ap2) i_memmove ((ap1), (ap2), sizeof (va_list))
#  else /* va_list is a pointer */
#    define VA_COPY(ap1, ap2) ((ap1) = (ap2))
#  endif /* va_list is a pointer */
#endif

/* Provide convenience macros for handling structure
 * fields through their offsets.
 */
#define STRUCT_OFFSET(struct_p, member) \
    ((long) ((char *) &((struct_p)->member) - (char *) (struct_p)))
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
#  if defined (__GNUC__) && !defined (__STRICT_ANSI__) && !defined (__cplusplus)
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
#  define __attr_format__(format_idx, arg_idx) \
	__attribute__((format (printf, format_idx, arg_idx)))
#  define __attr_format_arg__(arg_idx) \
	__attribute__((format_arg (arg_idx)))
#  define __attr_unused__ __attribute__((unused))
#  define __attr_noreturn__ __attribute__((noreturn))
#  define __attr_const__ __attribute__((const))
#else
#  define __attr_format__(format_idx, arg_idx)
#  define __attr_format_arg__(arg_idx)
#  define __attr_unused__
#  define __attr_noreturn__
#  define __attr_const__
#  define __attr_unused__
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
#ifdef DISABLE_CHECKS
#  define i_assert(expr)
#  define return_if_fail(expr)
#  define return_val_if_fail(expr,val)
#elif defined (__GNUC__) && !defined (__STRICT_ANSI__)

#define i_assert(expr)			STMT_START{			\
     if (!(expr))							\
       i_panic("file %s: line %d (%s): assertion failed: (%s)",		\
		__FILE__,							\
		__LINE__,							\
		__PRETTY_FUNCTION__,					\
		#expr);			}STMT_END

#define return_if_fail(expr)		STMT_START{			\
     if (!(expr))							\
       {								\
	 i_warning("file %s: line %d (%s): assertion `%s' failed.",	\
		__FILE__,						\
		__LINE__,						\
		__PRETTY_FUNCTION__,					\
		#expr);							\
	 return;							\
       };				}STMT_END

#define return_val_if_fail(expr,val)	STMT_START{			\
     if (!(expr))							\
       {								\
	 i_warning("file %s: line %d (%s): assertion `%s' failed.",	\
		__FILE__,						\
		__LINE__,						\
		__PRETTY_FUNCTION__,					\
		#expr);							\
	 return val;							\
       };				}STMT_END

#else /* !__GNUC__ */

#define i_assert(expr)			STMT_START{		\
     if (!(expr))						\
       i_panic("file %s: line %d: assertion failed: (%s)",	\
	      __FILE__,						\
	      __LINE__,						\
	      #expr);			}STMT_END

#define return_if_fail(expr)		STMT_START{		\
     if (!(expr))						\
       {							\
	 i_warning("file %s: line %d: assertion `%s' failed.",	\
		__FILE__,					\
		__LINE__,					\
		#expr);						\
	 return;						\
       };				}STMT_END

#define return_val_if_fail(expr, val)	STMT_START{		\
     if (!(expr))						\
       {							\
	 i_warning("file %s: line %d: assertion `%s' failed.",	\
		__FILE__,					\
		__LINE__,					\
		#expr);						\
	 return val;						\
       };				}STMT_END

#endif

#endif
