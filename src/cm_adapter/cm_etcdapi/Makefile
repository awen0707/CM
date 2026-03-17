BASE=$(shell pwd)
subdir = src/cm_adapter/cm_etcdapi
CM_TOP_BUILDDIR = ../../..


BASE_BUILD_PATH = $(CM_TOP_BUILDDIR)/build
include $(BASE_BUILD_PATH)/Makefile.global

DESTDIR = $(CM_TOP_BUILDDIR)/output

all: libetcdapi.a libetcdapi.so

cm_etcdapi.o:
	$(CC) -c -fPIC -shared $(CXXFLAGS) $(CPPFLAGS) cm_etcdapi.cpp -o cm_etcdapi.o

libetcdapi.so: libetcdapi.a
	$(CC) -fPIC -shared $(CXXFLAGS) $(CPPFLAGS) *.o -o libetcdapi.so -lpthread

libetcdapi.a: output cm_etcdapi.o
	ar -crv $@ *.o

output:
	ar -x ${3RD_PATH}/kernel/dependency/etcd/comm/lib/libclientv3.a

install: all

clean:
	rm -rf libetcdapi.so libetcdapi.a libclientv3.a *.o *depend
