conf.set(
  'HAVE_ATTR_NONSTRING',
  cc.compiles(
    import('fs').read('nonstring.c'),
    args: '-Werror',
    name: 'nonstring attribute',
  ),
  description: 'define if you have nonstring attribute',
)
