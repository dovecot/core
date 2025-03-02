#!/usr/bin/env perl
use strict;
use warnings;
use version;
use 5.010;

my ($input_path, $pro_edition) = ($ARGV[0], $ARGV[1]);

# output renames
print "static const struct setting_history_rename settings_history_core_renames[] = {\n";
my $f;
open $f, "<:encoding(utf8)", $input_path or die "$!";
my $prev_version = "";
while (<$f>) {
  chomp;
  if (/^rename\t/) {
    my ($type, $old_key, $new_key, $ce_version, $pro_version) = split("\t");
    my $version = $pro_edition ? $pro_version : $ce_version;
    if ($version ne "") {
      die "bad version: $version" if $version !~ /^((\d+)\.)*(\d+)$/;
      print "  { \"$old_key\", \"$new_key\", \"$version\" },\n";
      if ($prev_version ne "") {
	die "Bad version sorting order" if version->parse($version) > version->parse($prev_version);
      }
      $prev_version = $version;
    }
  } elsif (! /^default\t/) {
    die "Unknown line: $_";
  }
}
close $f;
print "};\n";

# output defaults
print "static const struct setting_history_default settings_history_core_defaults[] = {\n";
open $f, "<:encoding(utf8)", $input_path or die "$!";
while (<$f>) {
  chomp;
  if (/^default\t/) {
    my ($type, $key, $old_value, $ce_version, $pro_version) = split("\t");
    my $version = $pro_edition ? $pro_version : $ce_version;
    if ($version ne "") {
      die "bad version: $version" if $version !~ /^((\d+)\.)*(\d+)$/;
      print "  { \"$key\", \"$old_value\", \"$version\" },\n";
      if ($prev_version ne "") {
	die "Bad version sorting order" if version->parse($version) > version->parse($prev_version);
      }
      $prev_version = $version;
    }
  }
}
close $f;
print "};\n";
