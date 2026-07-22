opt_sodium = get_option('sodium')
ext_sodium = dependency('libsodium', required: opt_sodium)

# libsodium is only used for argon2: fail if crypto_pwhash_str_verify() is missing.
if ext_sodium.found() and not cc.has_function(
  'crypto_pwhash_str_verify',
  dependencies: ext_sodium,
  required: opt_sodium,
)
  ext_sodium = dependency('', required: false)
endif

conf.set('HAVE_LIBSODIUM', ext_sodium.found(), description: 'Have libsodium')
summary({'Sodium': ext_sodium}, section: 'Features')
