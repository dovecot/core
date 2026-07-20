# Not really used, but it exists in dovecot.h so maybe plugins need it.
conf.set(
  'HAVE_STRUCT_IOVEC',
  cc.has_type(
    'struct iovec',
    prefix : libc_prefix,
  ),
)

# OpenBSD's struct ucred.
conf.set(
  'HAVE_STRUCT_SOCKPEERCRED',
  cc.has_type(
    'struct sockpeercred',
    prefix: '\n'.join(
      [
        '#include <sys/types.h>',
        '#include <sys/socket.h>',
      ],
    ),
  ),
)

stat_prefix = '\n'.join(
  [
    '#include <sys/types.h>',
    '#include <sys/stat.h>',
    '#include <unistd.h>',
  ],
)

try_libc_members = [
  {
    'type': 'struct dirent',
    'member': 'd_type',
    'symbol': 'HAVE_DIRENT_D_TYPE',
    'prefix': '#include <dirent.h>',
  },
  {
    'type': 'struct stat',
    'member': 'st_mtim.tv_nsec',
    'symbol': 'HAVE_STAT_XTIM',
    'prefix': stat_prefix,
  },
  {
    'type': 'struct stat',
    'member': 'st_mtimespec.tv_nsec',
    'symbol': 'HAVE_STAT_XTIMESPEC',
    'prefix': stat_prefix,
  },

  # BSD.
  {
    'type': 'struct statvfs',
    'member': 'f_mntfromname',
    'symbol': 'HAVE_STATVFS_MNTFROMNAME',
    'prefix': '#include <sys/types.h>\n#include <sys/statvfs.h>',
  },
  {
    'type': 'struct statfs',
    'member': 'f_mntfromname',
    'symbol': 'HAVE_STATFS_MNTFROMNAME',
    'prefix': '#include <sys/param.h>\n#include <sys/mount.h>',
  },
]

foreach entry : try_libc_members
  type = entry['type']
  member = entry['member']
  symbol = entry['symbol']
  prefix = entry['prefix']

  conf.set(
    symbol,
    cc.has_member(type, member, prefix: prefix),
    description: f'have @type@.@member@',
  )
endforeach
