BASE=$(shell pwd)
CM_TOP_BUILDDIR = ../../..
BASE_BUILD_PATH = $(CM_TOP_BUILDDIR)/build
include $(BASE_BUILD_PATH)/Makefile.global
subdir = src/cm_communication/cm_feconnect

OBJS = $(patsubst %.cpp,%.o,$(wildcard *.cpp))

all: libcmclient.a libcmclient.so

libcmclient.so:
	$(CC) -fPIC -shared $(CXXFLAGS) $(CPPFLAGS) $(wildcard *.cpp) -o libcmclient.so

libcmclient.a: $(OBJS)
	ar crs $@ $^

install:all

clean:
	rm -f $(OBJS) libcmclient.a libcmclient.so *.depend
