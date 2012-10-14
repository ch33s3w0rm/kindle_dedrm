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

import os
import re
import sys
import traceback

import alfcrypto  # Modified.
import kgenpids
import mobidedrm
import topazextract

def remove_drm(infile, outdir, tokenlist):
  # TODO: Ignore read errors (IOError), return 1.
  print '\nProcessing book file: ' + infile
  inbase, inext = os.path.splitext(infile)
  if inbase.endswith('.nodrm'):
    if outdir is None:
      # TODO: Copy to outdir if does not exist with nodrm.
      print 'Ignoring nodrm file: ' + infile
    outfile = infile
  else:
    outfile = '%s.nodrm%s' % (inbase, inext)
  if outdir:
    outfile = os.path.join(outdir, os.path.basename(outfile))
  if os.path.exists(outfile):
    print 'Ignoring input because nodrm exists: ' + outfile
    return
  header = file(infile, 'rb').read(68)
  if (header.startswith('PK\3\4') or 
      header.startswith('PK\1\2') or
      header.startswith('PK\5\6')):
    # .htmlz files created from topaz look line this
    format = 'nodrm-zip'
  elif header.startswith('TPZ'):
    format = 'topaz'
    raise NotImplementedError('Topaz files not implemented.')
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
      raise RuntimeError('Unknown PID or serial: ' + token)

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
      print ('WARNING: Running in slow mode. Please download the '
             'system-specific libraries to speed it up.')
  try:
    mb.processBook(pidlst)
  except (topazextract.TpzDRMError, mobidedrm.DrmException):
    # This can happen e.g. when the wrong PID or serial number is supplied.
    traceback.print_exc(file=sys.stdout)
    return 1
  print 'DRM removed.'
  # TODO: Add topaz support.
  if format == 'topaz':
    print 'Topaz format detected.'
    ext = 'htmlz'
    try:
      mb.getHTMLZip(of.name)
    finally:
      # TODO: Do without creating temporary files.
      mb.cleanup()
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
  mb.getMobiFile(outfile)


def usage():
  print 'Removes protection from Kindle/Mobipocket, Kindle/KF8, Kindle/Print_Replica and Kindle/Topaz ebooks'
  print 'Usage:'
  print '  %s --kindle=... [--outdir=] <infile> [...]'
  print '--kindle= is a comma-separated list of Kindle serial numbers (16'
  print 'characters) or PIDs (10 or 8 characters).'


def main(argv):
  print ('kindle_dedrm using MobiDeDrm v%s. '
    'Copyright 2008-2012 The Dark Reverser et al.' % mobidedrm.__version__)

  # Parse command-line flags.
  outdir = None
  had_kindle = False
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
      usage()
      return 0
    elif arg.startswith('--kindle='):
      tokenlist.extend(filter(None, arg.split('=', 1)[1].split(',')))
      had_kindle = True
    elif arg.startswith('--outdir='):
      if outdir is not None:
        raise RuntimeError('--outdir= specified multiple times.')
      outdir = arg.split('=', 1)[1]
    else:
      raise RuntimeError('Unknown command-line flag: ' + arg)
    i += 1
  infiles = argv[i:]
  if not infiles or not had_kindle:
    usage()
    return 1

  error_count = 0
  for infile in infiles:
    if remove_drm(infile, outdir, tokenlist):
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
