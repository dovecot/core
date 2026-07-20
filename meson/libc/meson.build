# Flexible array members are C99 and the project builds as gnu11, so an empty definition is
# always the right one. This mirrors what AC_C_FLEXIBLE_ARRAY_MEMBER emits for a C99
# compiler.
conf.set('FLEXIBLE_ARRAY_MEMBER', '')

libc_prefix = ''

subdir('typeof')
subdir('va-copy')
subdir('size-checks')
subdir('mem-align-size')
