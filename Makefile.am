bin_PROGRAMS=fusesmb fusesmb.cache
fusesmb_SOURCES=fusesmb.c hash.c smbctx.c stringlist.c configfile.c
fusesmb_cache_SOURCES = cache.c hash.c stringlist.c smbctx.c configfile.c
noinst_HEADERS = hash.h stringlist.h smbctx.h configfile.h

#  uncomment the following if fusesmb requires the math library

#EXTRA_DIST=fusesmb.lsm.in fusesmb.spec.in fusesmb.texinfo
EXTRA_DIST=fusesmb.conf.ex fusesmb.1 fusesmb.conf.5

#  if you write a self-test script named `chk', uncomment the
#  following and add `chk' to the EXTRA_DIST list
#TESTS=chk

#  build and install the .info pages
#info_TEXINFOS = fusesmb.texinfo
#fusesmb_TEXINFOS = gpl.texinfo

#  install the man pages
man_MANS=fusesmb.1 fusesmb.conf.5
