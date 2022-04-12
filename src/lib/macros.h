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
	((void *) (((uintptr_t) (ptr)) + ((size_t) (offset))))
#define CONST_PTR_OFFSET(ptr, offset) \
	((const void *) (((uintptr_t) (ptr)) + ((size_t) (offset))))

#define container_of(ptr, type, name) \
	(type *)((char *)(ptr) - offsetof(type, name) + \
		 COMPILE_ERROR_IF_TYPES_NOT_COMPATIBLE(ptr, &((type *) 0)->name))

/* Don't use simply MIN/MAX, as they're often defined elsewhere in include
   files that are included after this file generating tons of warnings. */
#define I_MIN(a, b)  (((a) < (b)) ? (a) : (b))
#define I_MAX(a, b)  (((a) > (b)) ? (a) : (b))

/* make it easier to cast from/to pointers. assumes that
   sizeof(uintptr_t) == sizeof(void *) and they're both the largest datatypes
   that are allowed to be used. so, long long isn't safe with these. */
#define POINTER_CAST(i) \
	((void *) (((uintptr_t)NULL) + (i)))
#define POINTER_CAST_TO(p, type) \
	((type)(uintptr_t)(p))

#ifndef VA_COPY
   #error "VA_COPY not defined"
#endif

/* Provide convenience macros for handling structure
 * fields through their offsets.
 */
#define STRUCT_MEMBER_P(struct_p, struct_offset) \
	((void *) ((char *) (struct_p) + (long) (struct_offset)))
#define CONST_STRUCT_MEMBER_P(struct_p, struct_offset) \
	((const void *) ((const char *) (struct_p) + (long) (struct_offset)))

/* Provide simple macro statement wrappers:
   STMT_START { statements; } STMT_END;
   can be used as a single statement, as in
   if (x) STMT_START { ... } STMT_END; else ... */
#if !(defined (STMT_START) && defined (STMT_END))
#  define STMT_START do
#  define STMT_END while (0)
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

/* Macros to provide type safety for callback functions' context parameters.
   This is used like:

   // safe-api.h file:
   typedef void safe_callback_t(struct foo *foo);

   void safe_run(safe_callback_t *callback, void *context);
   #define safe_run(callback, context) \
       safe_run((safe_callback_t *)callback, \
       TRUE ? context : CALLBACK_TYPECHECK(callback, void (*)(typeof(context))))

   // safe-api.c file:
   #undef safe_run
   void safe_run(safe_callback_t *callback, void *context)
   {
       callback(context);
   }

   // in caller code:
   static void callback(struct foo *foo);
   struct foo *foo = ...;
   safe_run(callback, foo);

   The first step is to create the callback function in a normal way. Type
   safety is added to it by creating a macro that overrides the function and
   checks the callback type safety using CALLBACK_TYPECHECK().

   The CALLBACK_TYPECHECK() macro works by giving a compiling failure if the
   provided callback function isn't compatible with the specified function
   type parameter. The function type parameter must use typeof(context) in
   place of the "void *context" parameter, but otherwise use exactly the same
   function type as what the callback is. The macro then casts the given
   callback function into the type with "void *context".
*/
#ifdef HAVE_TYPE_CHECKS
#  define CALLBACK_TYPECHECK(callback, type) \
	(COMPILE_ERROR_IF_TRUE(!__builtin_types_compatible_p( \
		typeof(&callback), type)) ? 1 : 0)
#else
#  define CALLBACK_TYPECHECK(callback, type) 0
#endif

#if (__GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ > 0)) && \
	!defined(__cplusplus) && !defined(STATIC_CHECKER)
#  define COMPILE_ERROR_IF_TRUE(condition) \
	(sizeof(char[1 - 2 * ((condition) ? 1 : 0)]) > 0 ? FALSE : FALSE)
#else
#  define COMPILE_ERROR_IF_TRUE(condition) FALSE
#endif

#ifdef HAVE_TYPE_CHECKS
#  define COMPILE_ERROR_IF_TYPES_NOT_COMPATIBLE(_a, _b) \
	COMPILE_ERROR_IF_TRUE( \
		!__builtin_types_compatible_p(typeof(_a), typeof(_b)))
#define COMPILE_ERROR_IF_TYPES2_NOT_COMPATIBLE(_a1, _a2, _b) \
	COMPILE_ERROR_IF_TRUE( \
		!__builtin_types_compatible_p(typeof(_a1), typeof(_b)) && \
		!__builtin_types_compatible_p(typeof(_a2), typeof(_b)))
#  define TYPE_CHECKS(return_type, checks, func) \
	(FALSE ? (return_type)(checks) : (func))
#else
#  define COMPILE_ERROR_IF_TYPES_NOT_COMPATIBLE(_a, _b) 0
#  define COMPILE_ERROR_IF_TYPES2_NOT_COMPATIBLE(_a1, _a2, _b) 0
#  define TYPE_CHECKS(return_type, checks, func) (func)
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
#  define i_assert(expr)			STMT_START{			\
     if (unlikely(!(expr)))						\
       i_panic("file %s: line %d (%s): assertion failed: (%s)",		\
		__FILE__,						\
		__LINE__,						\
		__func__,					\
		#expr);			}STMT_END
#endif

/* Convenience macro to test the versions of dovecot. */
#define DOVECOT_PREREQ(maj, min, micro) \
	((DOVECOT_VERSION_MAJOR << 24) + \
	 (DOVECOT_VERSION_MINOR << 16) + \
	 DOVECOT_VERSION_MICRO >= ((maj) << 24) + ((min) << 16) + (micro))

#ifdef __cplusplus
#  undef STATIC_ARRAY
#  define STATIC_ARRAY
#endif

/* Convenience wrappers for initializing a struct with zeros, although it can
   be used for replacing other memset()s also.

   // NOTE: This is the correct way to zero the whole array
   char arr[5]; i_zero(&arr);
   // This will give compiler error (or zero only the first element):
   char arr[5]; i_zero(arr);
*/
#define i_zero(p) \
	memset(p, 0 + COMPILE_ERROR_IF_TRUE(sizeof(p) > sizeof(void *)), sizeof(*(p)))
#define i_zero_safe(p) \
	safe_memset(p, 0 + COMPILE_ERROR_IF_TRUE(sizeof(p) > sizeof(void *)), sizeof(*(p)))

#define ST_CHANGED(st_a, st_b) \
	((st_a).st_mtime != (st_b).st_mtime || \
	 ST_MTIME_NSEC(st_a) != ST_MTIME_NSEC(st_b) || \
	 (st_a).st_size != (st_b).st_size || \
	 (st_a).st_ino != (st_b).st_ino)

#ifdef HAVE_UNDEFINED_SANITIZER
# define ATTR_NO_SANITIZE(x) __attribute__((no_sanitize((x))))
#else
# define ATTR_NO_SANITIZE(x)
#endif

/* gcc and clang do this differently, see
   https://gcc.gnu.org/onlinedocs/gcc-10.2.0/gcc/Common-Function-Attributes.html */
#ifdef HAVE_FSANITIZE_UNDEFINED
# ifdef __clang__
#  define ATTR_NO_SANITIZE_UNDEFINED ATTR_NO_SANITIZE("undefined")
# else
#  define ATTR_NO_SANITIZE_UNDEFINED __attribute__((no_sanitize_undefined))
# endif
#else
# define ATTR_NO_SANITIZE_UNDEFINED
#endif

#ifdef HAVE_FSANITIZE_INTEGER
# define ATTR_NO_SANITIZE_INTEGER ATTR_NO_SANITIZE("integer")
# define ATTR_NO_SANITIZE_IMPLICIT_CONVERSION ATTR_NO_SANITIZE("implicit-conversion")
#else
# define ATTR_NO_SANITIZE_INTEGER
# define ATTR_NO_SANITIZE_IMPLICIT_CONVERSION
#endif

/* negate enumeration flags in a way that avoids implicit conversion */
#ifndef STATIC_CHECKER
#  define ENUM_NEGATE(x) \
	((unsigned int)(~(x)) + COMPILE_ERROR_IF_TRUE(sizeof((x)) > sizeof(int) || (x) < 0 || (x) > INT_MAX))
#else
/* clang scan-build keeps complaining about x > 2147483647 case, so disable the
   sizeof check. */
#  define ENUM_NEGATE(x) ((unsigned int)(~(x)))
#endif

#endif
