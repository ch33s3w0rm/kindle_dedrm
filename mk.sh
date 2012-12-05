#! /bin/bash --
set -ex
rm -f mk.zip
echo 'import kindle_dedrm; import sys; sys.exit(kindle_dedrm.main(sys.argv))' >__main__.py
zip -9 mk.zip alfcrypto.py kgenpids.py kindle_dedrm.py mobidedrm.py \
  topazextract.py __main__.py alfcrypto.c
rm -f __main__.py
(echo '#! /bin/sh
#
# kindle_dedrm: Python 2.x script for removing DRM from Kindle and .prc e-books
#
# Run this file with python2.6 or python2.7, or unzip it to see its source.
# It also works with python2.5 and python2.4 on Unix, but it is not recommended
# because of speed (missing ctypes).
# It does not work with Python 2.3 or earlier.
# It does not work with Python 3.0 or later.
#

type python2.7 >/dev/null 2>&1 && exec python2.7 -- "$0" ${1+"$@"}
type python2.6 >/dev/null 2>&1 && exec python2.6 -- "$0" ${1+"$@"}
type python2.5 >/dev/null 2>&1 && PYTHONPATH="$0:$PYTHONPATH" exec python2.5 -c \
    "import kindle_dedrm, sys; sys.exit(kindle_dedrm.main(sys.argv))" ${1+"$@"}
type python2.4 >/dev/null 2>&1 && PYTHONPATH="$0:$PYTHONPATH" exec python2.4 -c \
    "import kindle_dedrm, sys; sys.exit(kindle_dedrm.main(sys.argv))" ${1+"$@"}
PYTHONPATH="$0:$PYTHONPATH" exec python -c \
    "import kindle_dedrm, sys; sys.exit(kindle_dedrm.main(sys.argv))" ${1+"$@"}
exit 1
'
 cat mk.zip
) >kindle_dedrm
chmod 755 kindle_dedrm
: mk.sh OK.
