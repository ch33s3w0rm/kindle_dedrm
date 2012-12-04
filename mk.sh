#! /bin/bash --
set -ex
rm -f mk.zip
echo 'import kindle_dedrm; import sys; sys.exit(kindle_dedrm.main(sys.argv))' >__main__.py
zip -9 mk.zip alfcrypto.py kgenpids.py kindle_dedrm.py mobidedrm.py \
  topazextract.py __main__.py alfcrypto.c
rm -f __main__.py
(echo '#! /bin/sh
#
# kindle_dedrm: command-line Kindle DRM remover.
#
# Run this file with python2.6 or python2.7, or unzip it to see its source.
# It does not work with Python 2.5 or earlier.
# It does not work with Python 3.0 or later.
#

type -p python2.7 >/dev/null 2>&1 && exec python2.7 -- "$0" ${1+"$@"}
type -p python2.6 >/dev/null 2>&1 && exec python2.6 -- "$0" ${1+"$@"}
exec python -- "$0" ${1+"$@"}
exit 1
'
 cat mk.zip
) >out/kindle_dedrm
chmod 755 out/kindle_dedrm
: mk.sh OK.
