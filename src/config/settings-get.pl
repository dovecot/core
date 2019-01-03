#!/usr/bin/env perl
use strict;

print "/* WARNING: THIS FILE IS GENERATED - DO NOT PATCH!\n";
print "   It's not enough alone in any case, because the defaults may be\n";
print "   coming from the individual *-settings.c in some situations. If you\n";
print "   wish to modify defaults, change the other *-settings.c files and\n";
print "   just delete this file. This file will be automatically regenerated\n";
print "   by make. (This file is distributed in the tarball only because some\n";
print "   systems might not have Perl installed.) */\n";
print '#include "lib.h"'."\n";
print '#include "array.h"'."\n";
print '#include "ipwd.h"'."\n";
print '#include "var-expand.h"'."\n";
print '#include "file-lock.h"'."\n";
print '#include "fsync-mode.h"'."\n";
print '#include "hash-format.h"'."\n";
print '#include "net.h"'."\n";
print '#include "unichar.h"'."\n";
print '#include "hash-method.h"'."\n";
print '#include "settings-parser.h"'."\n";
print '#include "all-settings.h"'."\n";
print '#include <stddef.h>'."\n";
print '#include <unistd.h>'."\n";
print '#define CONFIG_BINARY'."\n";
print 'extern buffer_t config_all_services_buf;';

my @services = ();
my @service_ifdefs = ();
my %parsers = {};

foreach my $file (@ARGV) {
  my $f;
  open($f, $file) || die "Can't open $file: $@";
  
  my $state = 0;
  my $file_contents = "";
  my $externs = "";
  my $code = "";
  my %funcs;
  my $cur_name = "";
  my $ifdef = "";
  my $state_ifdef = 0;
  
  while (<$f>) {
    my $write = 0;
    if ($state == 0) {
      if (/struct .*_settings \{/ ||
	  /struct setting_define.*\{/ ||
	  /struct .*_default_settings = \{/) {
	$state++;
      } elsif (/^struct service_settings (.*) = \{/) {
	$state++;
	if ($ifdef eq "") {
	  $state_ifdef = 0;
	} else {
	  $_ = $ifdef."\n".$_;
	  $state_ifdef = 1;
	}
	push @services, $1;
	push @service_ifdefs, $ifdef;
      } elsif (/^(static )?const struct setting_parser_info (.*) = \{/) {
	$cur_name = $2;
	$state++ if ($cur_name !~ /^\*default_/);
      } elsif (/^extern const struct setting_parser_info (.*);/) {
	$externs .= "extern const struct setting_parser_info $1;\n";
      } elsif (/\/\* <settings checks> \*\//) {
	$state = 4;
	$code .= $_;
      }
      
      if (/(^#ifdef .*)$/ || /^(#if .*)$/) {
	$ifdef = $1;
      } else {
	$ifdef = "";
      }
      
      if (/#define.*DEF/ || /^#undef.*DEF/ || /ARRAY_DEFINE_TYPE.*_settings/) {
	$write = 1;
	$state = 2 if (/\\$/);
      }
    } elsif ($state == 2) {
      $write = 1;
      $state = 0 if (!/\\$/);
    } elsif ($state == 4) {
      $code .= $_;
      $state = 0 if (/\/\* <\/settings checks> \*\//);
    }
    
    if ($state == 1 || $state == 3) {
      if ($state == 1) {
	if (/\.module_name = "(.*)"/) {
	  $parsers{$cur_name} = $1;
	}
	if (/DEFLIST.*".*",(.*)$/) {
	  my $value = $1;
	  if ($value =~ /.*&(.*)\)/) {
	    $parsers{$1} = 0;
	    $externs .= "extern const struct setting_parser_info $1;\n";
	  } else {
	    $state = 3;
	  }
	}
      } elsif ($state == 3) {
	if (/.*&(.*)\)/) {
	  $parsers{$1} = 0;
	}        
      }
      
      s/^static const (struct master_settings master_default_settings)/$1/;

      $write = 1;
      if (/};/) {
	$state = 0;
	if ($state_ifdef) {
	  $_ .= "#endif\n";
	  $state_ifdef = 0;
	}
      }
    }
  
    $file_contents .= $_ if ($write);
  }
  
  print "/* $file */\n";
  print $externs;
  print $code;
  print $file_contents;

  close $f;
}

print "static struct service_settings *config_all_services[] = {\n";

for (my $i = 0; $i < scalar(@services); $i++) {
  my $ifdef = $service_ifdefs[$i];
  print "$ifdef\n" if ($ifdef ne "");
  print "\t&".$services[$i].",\n";
  print "#endif\n" if ($ifdef ne "");
}
print "};\n";
print "buffer_t config_all_services_buf = {\n";
print "\tconfig_all_services, sizeof(config_all_services), { NULL, }\n";
print "};\n";

print "const struct setting_parser_info *all_default_roots[] = {\n";
print "\t&master_service_setting_parser_info,\n";
print "\t&master_service_ssl_setting_parser_info,\n";
print "\t&smtp_submit_setting_parser_info,\n";
foreach my $name (sort(keys %parsers)) {
  my $module = $parsers{$name};
  next if (!$module);

  print "\t&".$name.", \n";
}
print "\tNULL\n";
print "};\n";
print "const struct setting_parser_info *const *all_roots = all_default_roots;\n";
print "ARRAY_TYPE(service_settings) *default_services = &master_default_settings.services;\n";
