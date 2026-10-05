fs = import('fs')

# Keep in sync with UCD_VERSION in src/lib/Makefile.am.
ucd_version = '18.0.0'

ucd_filenames = [               # Downloadable filenames.
  'CaseFolding.txt',
  'CompositionExclusions.txt',
  'DerivedBidiClass.txt',
  'DerivedCoreProperties.txt',
  'DerivedJoiningType.txt',
  'DerivedNormalizationProps.txt',
  'emoji-data.txt',
  'GraphemeBreakProperty.txt',
  'GraphemeBreakTest.txt',
  'NormalizationTest.txt',
  'PropertyValueAliases.txt',
  'PropList.txt',
  'Scripts.txt',
  'SpecialCasing.txt',
  'UnicodeData.txt',
  'WordBreakProperty.txt',
  'IdnaMappingTable.txt',
  'IdnaTestV2.txt',
]
ucd_files = []               # Downloadable file objects.
ucd_files_dir = meson.current_source_dir()

# Check if the downloadable UCD files are already available and create the list of file
# objects pointing to them.
foreach filename : ucd_filenames
  if not fs.is_file(filename)
    # Some or all of the downloadable UCD files are not available. Reset the list of file
    # objects and break out so we can attempt to download them below.
    ucd_files = []
    break
  endif
  ucd_files += files(filename)
endforeach

# A git checkout never ships the downloaded files, so a copy found here is a leftover from
# an autotools build. Ignore those and force the download of the files.
if ucd_files.length() != 0 and have_git_tree
  warning('Found unicode UCD files in the source tree of a git checkout. ' +
          'Going to assume those unicode UCD files are leftover from autotools')
  ucd_files = []
endif

# Ignore UCD files that are not for ucd_version. UnicodeData.txt has no version header, so
# it's skipped here, but ignored along with the others.
if ucd_files.length() != 0
  foreach filename : ucd_filenames
    if filename == 'UnicodeData.txt'
      continue
    endif
    header = fs.read(filename).substring(0, 1024)
    if not header.contains(f'-@ucd_version@.txt') and \
       not header.contains(f'Version: @ucd_version@')
      warning(f'Found unicode UCD files not matching version @ucd_version@. ' +
              'Going to ignore them and download the files')
      ucd_files = []
      break
    endif
  endforeach
endif

if ucd_files.length() == 0
  # The UCD files are at least partially unavailable. Attempt to download them.
  prog_wget = find_program('wget')

  # Download the files again when ucd_version changes.
  ucd_version_stamp = configure_file(
    output: 'ucd-version.h',
    configuration: {'UCD_VERSION': f'"@ucd_version@"'},
  )

  foreach filename : ucd_filenames
    ucd_files += custom_target(
      filename,
      output: filename,
      depend_files: ucd_version_stamp,
      command: [
        prog_wget,
        f'https://dovecot.org/res/@filename@',
        '--quiet',
        '--no-use-server-timestamps',
        '--output-document',
        '@OUTPUT@',
      ],
    )
  endforeach

  ucd_files_dir = meson.current_build_dir()
endif

# The UCD files are gitignored, so `meson dist` needs to copy them over from the build
# directory into the source directory in the tarball. This is so a tarball that ships with
# them can build without network access.
meson.add_dist_script(
  generated_dist_script,
  ucd_files_dir,                # Where the downloaded files can be found.
  'src/lib/ucd',                # Where the unicode UCD files should go in the tarball.
  ucd_filenames,                # The downloaded filenames.
)
