have_fallocate = cc.run(
    import('fs').read('fallocate.c'),
    name: 'POSIX fallocate()',
).returncode() == 0
conf.set('HAVE_POSIX_FALLOCATE', have_fallocate)
