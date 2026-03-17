BASE=$(shell pwd)
subdir = src/cm_adapter/cm_etcd_adapter
CM_TOP_BUILDDIR = ../../..


BASE_BUILD_PATH = $(CM_TOP_BUILDDIR)/build
include $(BASE_BUILD_PATH)/Makefile.global

DESTDIR = $(CM_TOP_BUILDDIR)/output

ifeq ($(ENABLE_ETCD), ON)
    OBJS = cm_ddb_etcd.o cm_ddb_etcd_arbitrate.o
else
    OBJS = cm_ddb_etcd_stub.o
    CXXFLAGS += -fstack-protector-all
endif

all: libcmetcdadapter.a libcmetcdadapter.so

libcmetcdadapter.so:
	$(CC) -fPIC -shared $(CXXFLAGS) $(CPPFLAGS) $(patsubst %.o,%.cpp,$(OBJS)) -o libcmetcdadapter.so

libcmetcdadapter.a: $(OBJS)
	ar crs $@ $^

clean:
	rm -rf $(OBJS) libcmetcdadapter.a libcmetcdadapter.so *.depend

install:all
