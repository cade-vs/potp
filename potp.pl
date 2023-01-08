#!/usr/bin/perl
##############################################################################
##
##  POTP perl-based OTP shell
##  2023 (c) Vladi Belperchinov-Shabanski "Cade"
##  <cade@noxrun.com> <cade@bis.bg> <cade@cpan.org>
##
##  LICENSE: GPLv2
##
##############################################################################
use strict;
use Data::Tools;
use Data::Dumper;
use MIME::Base32;
use Math::BigInt;
use Digest::SHA1 qw(sha1);
use Digest::HMAC qw(hmac);

my $DATA_DIR = $ENV{ 'HOME' } . "/.potp";

my $DEBUG;
my $HELP = <<END_OF_HELP;
(c) Vladi Belperchinov-Shabanski "Cade"    <cade\@noxrun.com> <cade\@bis.bg>
Distributed under GNU GPLv2 license. http://cade.nuxron.com/projects/potp

usage: $0 <options> <name>

options:

  -h       -- print help
  -l       -- list available OTP entries
  -d       -- increase debug level
  -a dir   -- set data dir to hold resrei database (default is ~/.resrei)
  -y       -- assume YES to all questions (disables -n)
  -n       -- assume NO  to all questions (disables -y)
  -q       -- suppress non-urgent messages

name:

  OTP entry (file) name to request for current OTP value

default data directory in use:

  $DATA_DIR

example OTP entry file:

  # begin OTP file
  key=HFGFJDKSURHFKDFJGK
  digits=6
  period=30
    
note: period is in seconds

supported file formats, searched for in the following order: 

  1. GPG encrypted text               (*.txt.gpg)
  2. GPG encrypted ASCII-armored text (*.txt.asc)
  3. plaint text                      (*.txt)

END_OF_HELP

my $READLINE;
my $opt_always_yes;
my $opt_always_no;
my $opt_allow_past;
my $opt_no_colors;
my $opt_quiet;
my $opt_command;

our @args;
our @args2;
while( @ARGV )
  {
  $_ = shift;
  if( /^--+$/io )
    {
    push @args2, @ARGV;
    last;
    }
  if( /-a/ )
    {
    $DATA_DIR = shift;
    next;
    }
  if( /-y/ )
    {
    $opt_always_yes = 1;
    $opt_always_no  = 0;
    next;
    }
  if( /-n/ )
    {
    $opt_always_yes = 0;
    $opt_always_no  = 1;
    next;
    }
  if( /-l/ )
    {
    $opt_command = 'list';
    next;
    }
  if( /-q/ )
    {
    $opt_quiet = 1;
    next;
    }
  if( /^-d/ )
    {
    $DEBUG++;
    next;
    }
  if( /^(--?h(elp)?|help)$/io )
    {
    print $HELP;
    exit;
    }
  push @args, $_;
  }

if( @args == 0 and ! $opt_command )
  {
  print $HELP;
  exit;
  }

dir_path_ensure( $DATA_DIR ) or die "fatal: cannot access data dir [$DATA_DIR]\n";
chdir $DATA_DIR or die "fatal: cannot enter data dir [$DATA_DIR]\n";
print STDERR "using data dir: [$DATA_DIR]\n" if $DEBUG;

##############################################################################

if( $opt_command eq 'list' )
  {
  list_all_otp_names();
  }
else
  {
  show_otp( $_ ) for @args;
  }  

exit 0;

sub list_all_otp_names
{
  my @otp = grep /^([a-z_\-0-9]+)\.txt(\.(gpg|asc))?$/i, <*>;
  print "$_\n" for @otp;
}


sub show_otp
{
  my $name = shift;
  
  my $txt;
  $txt = cmd_read_from( 'gpg', '-d', "$name.txt.gpg" ) if ! $txt and -e "$name.txt.gpg";
  $txt = cmd_read_from( 'gpg', '-d', "$name.txt.asc" ) if ! $txt and -e "$name.txt.asc";
  $txt = file_load( "$name.txt" )                      if ! $txt and -e "$name.txt";
  
  my $hr = str2hash( $txt );
  print Dumper( $hr ) if $DEBUG;
  
  my $key = $hr->{ 'key'    } || $hr->{ 'k'    };
  my $dig = $hr->{ 'digits' } || $hr->{ 'd'    } ||  6;
  my $per = $hr->{ 'period' } || $hr->{ 'p'    } || 30;

  my $bckey = MIME::Base32::decode( $key );

  my $totp   = totp( $bckey );
  my $totp_s = $totp;

  $totp_s =~ s/(...)/$1 /g;
  
  print "\n";
  print "$name -->  $totp  [ $totp_s]\n";
  print "\n";
}

##############################################################################

sub totp
{
  my ( $secret, $digits, $tt ) = @_;

  my $X  = 30;
  my $T0 = 0;
  my $T  = int(( time() - $T0 ) / $X);

  return hotp( $secret, $T, $digits );
}


##############################################################################

# RFC4226!
sub hotp
{
    my ( $secret, $c, $digits ) = @_;

    # guess hex encoded
    $secret = join "", map chr hex, $secret =~ /(..)/g
        if $secret =~ /^[a-fA-F0-9]+$/;

    $c = new Math::BigInt( $c ) unless ref $c eq "Math::BigInt";

    $digits ||= 6;

    die unless length $secret >= 16; # 128-bit minimum
    die unless $digits >= 6 and $digits <= 10;

    ( my $hex = $c->as_hex ) =~ s/^0x(.*)/"0"x( 16 - length $1 ) . $1/e;
    my $bin = join '', map chr hex, $hex =~ /(..)/g; # pack 64-bit big endian
    my $hash = hmac $bin, $secret, \&sha1;
    my $offset = hex substr unpack("H*" => $hash), -1;
    my $dt = unpack "N" => substr $hash, $offset, 4;
    $dt &= 0x7fffffff; # 31-bit
    $dt %= (10 ** $digits); # limit range

    return sprintf "%0${digits}d", $dt;
}

##############################################################################
