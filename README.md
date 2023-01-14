
# SYNOPSIS

    potp.pl <options> <name>
    
    alias pp=potp.pl
    pp -l     # list all available data files
    pp steam  # show OTP for data file "steam"

# OPTIONS

    -h       -- print help
    -l       -- list available OTP entries
    -d       -- increase debug level
    -a dir   -- set data dir to hold resrei database (default is ~/.resrei)
    -y       -- assume YES to all questions (disables -n)
    -n       -- assume NO  to all questions (disables -y)
    -q       -- suppress non-urgent messages

# OTP DATA FILE NAME

  OTP entry (file) name to request for current OTP value

# DATA FILE DIRECTORY

default data directory in use:

  $HOME/.potp

# DATA FILE FORMAT

example OTP entry file:

    # begin OTP file
    key=HFGFJDKSURHFKDFJGK
    digits=6
    period=30
    
  notes: 

      'key' is base64 encoded                
      'digits' is optional and defaults to 6
      'period' is in seconds, optional and defaults to 30

supported file formats, searched for in the following order: 

  1. GPG encrypted text               (*.txt.gpg)
  2. GPG encrypted ASCII-armored text (*.txt.asc)
  3. plaint text                      (*.txt)

# AUTHOR & LICENSE

    (c) Vladi Belperchinov-Shabanski "Cade"    <cade@noxrun.com> <cade@bis.bg>
    Distributed under GNU GPLv2 license. http://cade.nuxron.com/projects/potp

