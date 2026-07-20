assert(conf.get('HAVE_MMAP', 0) == 1, 'mmap() is required')

fs = import('fs')

if conf.get('HAVE_SYS_MMAN_H', 0) == 1
  if cc.links(
    fs.read('mremap.c').format(libc_prefix),
    name: 'Linux-compatible mremap()',
  )
    conf.set10('HAVE_LINUX_MREMAP', true)
  endif
endif

if cc.run(
  fs.read('mmap-conflict.c').format(libc_prefix),
  name: 'shared mmaps get updated by write()s',
).returncode() == 1
  conf.set10('MMAP_CONFLICTS_WRITE', true)
endif
