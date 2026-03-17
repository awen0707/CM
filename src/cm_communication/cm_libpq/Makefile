BASE=$(shell pwd)
CM_TOP_BUILDDIR = ../../..
BASE_BUILD_PATH = $(CM_TOP_BUILDDIR)/build
include $(BASE_BUILD_PATH)/Makefile.global
subdir = src/cm_communication/cm_libpq

DESTDIR = $(CM_TOP_BUILDDIR)/output

OBJS = $(patsubst %.cpp,%.o,$(wildcard *.cpp))


all: libcmpq.a libcmpq.so

libcmpq.so:
	$(CC) -fPIC -shared $(CXXFLAGS) $(CPPFLAGS) $(wildcard *.cpp) -o libcmpq.so

libcmpq.a: $(OBJS)
	ar crs $@ $^

install:all
	
uninstall:
	rm -f '$(DESTDIR)$(libdir)/libcmpq.a'
	rm -f '$(DESTDIR)$(includedir)/cm-libpq-fe.h'

clean:
	rm -f $(OBJS) libcmpq.a libcmpq.so *.depend
