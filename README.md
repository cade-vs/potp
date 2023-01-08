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
