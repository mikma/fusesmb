bin_PROGRAMS=fusesmb
bin_SCRIPTS=fusesmbcache
fusesmb_SOURCES=fusesmb.c 

#  uncomment the following if fusesmb requires the math library
fusesmb_LDADD=-lsmbclient -lpthread -lfuse

#EXTRA_DIST=fusesmb.lsm.in fusesmb.spec.in fusesmb.texinfo
EXTRA_DIST=fusesmbcache
#  if you write a self-test script named `chk', uncomment the
#  following and add `chk' to the EXTRA_DIST list
#TESTS=chk

#  build and install the .info pages
#info_TEXINFOS = fusesmb.texinfo
#fusesmb_TEXINFOS = gpl.texinfo

#  install the man pages
#man_MANS=fusesmb.1
