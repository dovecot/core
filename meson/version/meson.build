version_arr = dovecot_version.split('.')

if version_arr.length() < 2 or version_arr[0] == '' or version_arr[1] == ''
  error('Version broken: no major.minor in version', dovecot_version)
endif

# A version can carry a suffix, like '2.4-rc1' or '2.4.0-99+hash', on any of its
# components. Only the leading number of a component belongs to the numeric version, so
# strip the suffix off before converting. The macros are used in #if expressions, where a
# non-numeric value would be a compile error, so to_int() rejects invalid ones here.
version_major = version_arr[0].split('-')[0].split('+')[0].to_int()
version_minor = version_arr[1].split('-')[0].split('+')[0].to_int()

version_has_micro = version_arr.length() > 2
version_micro = 0
if version_has_micro
  version_micro = version_arr[2].split('-')[0].split('+')[0].to_int()
endif

conf.set('DOVECOT_VERSION_MAJOR', version_major)
conf.set('DOVECOT_VERSION_MINOR', version_minor)
conf.set('DOVECOT_VERSION_MICRO', version_micro)

# The configuration version is the leading x.y.z of the version, or just x.y for
# versions that carry no micro number.
dovecot_config_version = f'@version_major@.@version_minor@'
if version_has_micro
  dovecot_config_version += f'.@version_micro@'
endif
conf.set_quoted('DOVECOT_CONFIG_VERSION', dovecot_config_version)

summary(
  {
    'Version': dovecot_version,
    'Config version': dovecot_config_version,
  },
  section: 'Version',
)

conf.set_quoted('PACKAGE_NAME', 'Dovecot')
conf.set_quoted('PACKAGE_VERSION', dovecot_version)

if get_option('pro-build')
  # TODO: For doc/dovecot.conf.in and doc/index.html.in
  dovecot_asset_url = 'doc.dovecotpro.com'

  conf.set10('DOVECOT_PRO_BUILD', true)
  conf.set_quoted('DOVECOT_DOC_URL', 'https://doc.dovecotpro.com/')
  conf.set_quoted('DOVECOT_NAME', 'Dovecot Pro')
  conf.set_quoted('DOVECOT_EDITION', 'Pro')
  conf.set_quoted('PACKAGE_BUGREPORT', 'support@open-xchange.com')
  conf.set_quoted('PACKAGE_WEBPAGE', 'https://www.dovecotpro.com/')
  conf.set10('DOVECOT_PRO_EDITION', true)
  summary({'Edition' : 'Pro'}, section: 'Version')
else
  # TODO: For doc/dovecot.conf.in and doc/index.html.in
  dovecot_asset_url = 'doc.dovecot.org'

  conf.set_quoted('DOVECOT_DOC_URL', 'https://doc.dovecot.org/')
  conf.set_quoted('DOVECOT_NAME', 'Dovecot')
  conf.set_quoted('DOVECOT_EDITION', 'CE')
  conf.set_quoted('PACKAGE_BUGREPORT', 'dovecot@dovecot.org')
  conf.set_quoted('PACKAGE_WEBPAGE', 'https://www.dovecot.org/')
  summary({'Edition' : 'CE'}, section: 'Version')
endif
