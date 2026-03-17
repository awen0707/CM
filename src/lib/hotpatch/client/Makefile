#-------------------------------------------------------------------------
#
# Makefile--
#    Makefile for client hotpatch 
#
# IDENTIFICATION
#    src/lib/hotpatch/client/Makefile
#
#-------------------------------------------------------------------------

subdir = src/lib/hotpatch/client
CM_TOP_BUILDDIR = ../../../..
BASE_BUILD_PATH = $(CM_TOP_BUILDDIR)/build
include $(BASE_BUILD_PATH)/Makefile.global

OBJS = hotpatch_client.o

all: libhotpatchclient.a

libhotpatchclient.a: $(OBJS)
	ar crs $@ $^

clean:
	rm -f $(OBJS) libhotpatchclient.a *.depend

install:all
