BASE=$(shell pwd)
subdir = src/cm_adapter/cm_ddb_adapter
CM_TOP_BUILDDIR = ../../..
OPEN_CM_SRC_PATH = $(CM_TOP_BUILDDIR)/src
BASE_BUILD_PATH = $(CM_TOP_BUILDDIR)/build
CM_ADAPTER_PATH = $(OPEN_CM_SRC_PATH)/cm_adapter
include $(BASE_BUILD_PATH)/Makefile.global


DESTDIR = $(CM_TOP_BUILDDIR)/output

ifeq ($(ENABLE_ETCD), ON)
    SUBDIRS = $(CM_ADAPTER_PATH)/cm_etcdapi
endif

include $(BASE_BUILD_PATH)/common.mk

OBJS = cm_ddb_adapter.o

all: libcmddbadapter.a libcmddbadapter.so

libcmddbadapter.so:
	$(CC) -fPIC -shared $(CXXFLAGS) $(CPPFLAGS) cm_ddb_adapter.cpp -o libcmddbadapter.so

libcmddbadapter.a: $(OBJS)
	ar crs $@ $^

clean:
	rm -rf $(OBJS) libcmddbadapter.a libcmddbadapter.so *.depend

install: all
