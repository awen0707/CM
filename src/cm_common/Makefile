BASE=$(shell pwd)
CM_TOP_BUILDDIR = ../..
OPEN_CM_SRC_PATH = $(CM_TOP_BUILDDIR)/src
COMM_LIB_PATH = $(OPEN_CM_SRC_PATH)/lib
CM_ADAPTER_PATH = $(OPEN_CM_SRC_PATH)/cm_adapter

BASE_BUILD_PATH = $(CM_TOP_BUILDDIR)/build

include $(BASE_BUILD_PATH)/Makefile.global
subdir = src/cm_common

DESTDIR = $(CM_TOP_BUILDDIR)/output

CPPFLAGS += -I$(CJSON_DIRECTORY_INC) -I$(CGROUP_DIRECTORY_INC) -l:libsecurec.a

ifeq ($(ENABLE_MULTIPLE_NODES), NO)
    CXXFLAGS += -lcgroup
endif

OBJS = $(patsubst %.cpp,%.o,$(wildcard *.cpp)) $(COMM_LIB_PATH)/pq/port/path.o


all: libcmcommon.a libcmcommon.so config.h

libcmcommon.so:
	$(CC) -fPIC -shared $(CXXFLAGS) $(CPPFLAGS) $(wildcard *.cpp) -o libcmcommon.so

libcmcommon.a: $(OBJS)
	ar crs $@ $^

config.h:$(CM_TOP_BUILDDIR)/build/cmake/config.h.in
	ln -sf $(BASE)/../../build/cmake/config.h.in $(OPEN_CM_SRC_PATH)/include/cm/config.h

clean:
	rm -f $(OBJS) libcmcommon.a libcmcommon.so $(OPEN_CM_SRC_PATH)/include/cm/config.h *.depend

install:all
	mkdir -p $(DESTDIR)/share/config
	cp -rf ${CJSON_DIRECTORY_LIB}/libcjson.so* $(DESTDIR)/lib
	cp -rf ${SSL_DIRECTORY_LIB}/libcrypto.so* $(DESTDIR)/lib
	cp -rf ${SSL_DIRECTORY_LIB}/libssl.so* $(DESTDIR)/lib

