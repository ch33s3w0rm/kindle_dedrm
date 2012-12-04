#! /usr/bin/env python
# works with Python 2.6 and 2.7, won't work with Python 3.x

"""Kindle book DRM remover script.

Software downloads:

* https://apprenticealf.wordpress.com/2012/09/10/drm-removal-tools-for-ebooks/
* The latest tools_v5.3.1.zip can be downloaded from
  http://www.datafilehost.com/download-9c5f9950.html
* https://apprenticealf.wordpress.com/2010/11/18/dedrm-applescript-for-mac-os-x-10-5-10-6/

Corresponding documentation:

* https://apprenticealf.wordpress.com/2011/01/13/ebooks-formats-drm-and-you-%E2%80%94-a-guide-for-the-perplexed/
* http://wiki.mobileread.com/wiki/AZW
* http://wiki.mobileread.com/wiki/AZW4
* http://wiki.mobileread.com/wiki/Topaz
* http://wiki.mobileread.com/wiki/Mobi_unpack
"""

import errno
import os
import re
import sys
import traceback

import alfcrypto  # Modified.
import kgenpids
import mobidedrm
import topazextract


TOKEN_DOC = (
    'Specify either the 16-character device serial number (DSN,\n'
    'Kindle ID) of the Kindle (open the Settings menu in the Kindle\n'
    'and find it there or on http://kindle.com/ in your devices;\n'
    'usually starts with B0, and contains lots of numbers; there may\n'
    'be spaces inside) or the 10-character or the 8-character PID\n'
    '(personal ID) of an old Kindle.')


def remove_drm(infile, outdir, tokenlist, do_overwrite):
  # TODO: Ignore read errors (IOError), return 1.
  print '\nProcessing book file: ' + infile
  inbase, inext = os.path.splitext(infile)
  if inbase.endswith('.nodrm'):
    if outdir is None:
      # TODO: Copy to outdir if does not exist with nodrm.
      print 'Ignoring nodrm file: ' + infile
    outfile = infile
  else:
    outext = inext
    if inext == '.azw1':  # Amazon Topaz.
      # Calibre can't open it with another extension.
      outext = '.htmlz'
    outfile = '%s.nodrm%s' % (inbase, outext)
  if outdir:
    outfile = os.path.join(outdir, os.path.basename(outfile))
  if os.path.exists(outfile):
    if do_overwrite:
      print 'Will overwrite existing output file: ' + outfile
    else:
      print 'Ignoring input because nodrm exists: ' + outfile
      return
  try:
    header = file(infile, 'rb').read(68)
  except IOError, e:
    if e[0] != errno.EISDIR:
      raise
    print 'Ignoring directory.'
    return
  if (header.startswith('PK\3\4') or 
      header.startswith('PK\1\2') or
      header.startswith('PK\5\6')):
    # .htmlz files created from topaz look line this
    format = 'nodrm-zip'
  elif header.startswith('TPZ'):
    format = 'topaz'
  elif header[60 : 68] == 'BOOKMOBI':
    format = 'mobi'
  else:
    print 'Not a Mobi or Topaz book.'
    return 1
  #bookname = os.path.splitext(os.path.basename(path_to_ebook))[0]
  if format == 'topaz':
    mb = topazextract.TopazBook(infile)
  elif format == 'mobi':
    mb = mobidedrm.MobiBook(infile, announce=False)
    if mb.sect[0xC : 0xC + 2] == '\0\0':
      format = 'nodrm-mobi'
  elif format == 'nodrm-zip':
    pass
  else:
    assert 0, repr(format)
  print 'Detected input file format: ' + format
  if format.startswith('nodrm-'):
    print 'Copying to: ' + outfile
    del mb
    data = file(infile, 'rb').read()
    f = file(outfile, 'wb')
    try:
      f.write(data)
    finally:
      f.close()
    return
  pidlst = []
  serials = []
  for token in tokenlist:
    token = re.sub(r'\s+', '', token)
    if len(token) in (8, 10):
      pidlst.append(token)
    elif len(token) == 16:
      serials.append(token)
    else:
      print 'Unrecognized PID or serial %r specified in the command line.'
      print TOKEN_DOC
      sys.exit(2)

  title = mb.getBookTitle()
  md1, md2 = mb.getPIDMetaInfo()
  for serial in serials:
    kgenpids.getKindlePid(pidlst, md1, md2, serial)
  print 'Using PIDs: ' + ', '.join(pidlst)

  if alfcrypto.Pukall_Cipher is None:
    alfcrypto.load_crypto()
    mobidedrm.Pukall_Cipher = alfcrypto.Pukall_Cipher
    topazextract.Topaz_Cipher = alfcrypto.Topaz_Cipher
    if alfcrypto.is_slow:
      print ('WARNING: Running in slow mode. Please run on Linux, Windows or '
             'Mac OS X (i386 or x86_64) for fast operation.')
  try:
    mb.processBook(pidlst)
  except (topazextract.TpzDRMError, mobidedrm.DrmException), e:
    if str(e) == 'No keys passed.':
      print 'Removing DRM from this file needs the Kindle serial number or PID.'
      print 'Please specify it in --kindle=...'
      return 1
    # This can happen e.g. when the wrong PID or serial number is supplied.
    traceback.print_exc(file=sys.stdout)
    return 1
  print 'DRM removed.'
  if format == 'topaz':
    print 'Topaz format detected.'
    # Calibre can open such .htmlz files and convert them to .epub or .mobi
    # -- but only if the extension is .htmlz. That's why we have
    # outfile.endswith('.htmlz') by now.
    ext = 'htmlz'
    try:
      mb.getHTMLZip(outfile)
    finally:
      # TODO: Do without creating temporary files.
      mb.cleanup()
    mb = None
  elif mb.getPrintReplica():
    print 'Print Replica format detected.'
    ext = 'azw4'
  elif mb.getMobiVersion() >= 8:
    print 'Stand-alone KF8 format detected.'
    ext = 'azw3'
  else:
    print 'Generic Mobi format detected.'
    ext = 'mobi'
  print 'Recommend output extension: .' + ext
  if mb is not None:
    mb.getMobiFile(outfile)


def usage(argv0):
  print 'Removes protection from Kindle/Mobipocket, Kindle/KF8, Kindle/Print_Replica and Kindle/Topaz ebooks'
  print 'Usage:'
  print '  %s [<flag> ...] [--outdir=] <infile> [...]' % argv0
  print '--overwrite enables overwriting existing output files'
  print '--kindle= is a comma-separated list of Kindle serial numbers (16'
  print '  characters) or PIDs (10 or 8 characters). This is required for '
  print '  Kindle e-books, but they are not needed for .prc files with DRM.'
  print '  ' + TOKEN_DOC.replace('\n', '\n  ')

class Unbuffered:
  def __init__(self, stream):
    self.stream = stream
  def write(self, data):
    self.stream.write(data)
    self.stream.flush()
  def __getattr__(self, attr):
    return getattr(self.stream, attr)

def main(argv):
  sys.stdout=Unbuffered(sys.stdout)
  print ('kindle_dedrm using MobiDeDrm v%s. '
    'Copyright 2008-2012 The Dark Reverser et al.' % mobidedrm.__version__)

  # Parse command-line flags.
  outdir = None
  had_kindle = False
  do_overwrite = False
  tokenlist = []
  i = 1
  while i < len(argv):
    arg = argv[i]
    if arg == '--':
      i += 1
      break
    elif not arg.startswith('-'):
      break
    elif arg in ('--help', '-h', '-?'):
      usage(argv[0])
      return 0
    elif arg.startswith('--kindle='):
      tokenlist.extend(filter(None, arg.split('=', 1)[1].split(',')))
      had_kindle = True
    elif arg.startswith('--outdir='):
      if outdir is not None:
        print '--outdir= specified multiple times.'
        return 1
      outdir = arg.split('=', 1)[1]
    elif arg == '--overwrite':
      do_overwrite = True
    else:
      raise RuntimeError('Unknown command-line flag: ' + arg)
    i += 1
  infiles = argv[i:]
  if not infiles:
    usage(argv[0])
    return 1

  error_count = 0
  for infile in infiles:
    if remove_drm(infile, outdir, tokenlist, do_overwrite):
      error_count += 1

  print ''
  if error_count:
    ok_count = len(infiles) - error_count
    print 'Processed %s file%s successfully, %s with errors.' % (
       ok_count, 's' * (ok_count != 1), error_count)
    return 2
  elif len(infiles) == 1:
    print 'Processed a single file successfully.'
    return 0
  else:
    print 'Processed all %s file successfully.' % len(infiles)
    return 0


if __name__ == "__main__":
  sys.exit(main(sys.argv))
