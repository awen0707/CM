BASE=$(shell pwd)
subdir = src/cm_adapter/cm_dcc_adapter
CM_TOP_BUILDDIR = ../../..

BASE_BUILD_PATH = $(CM_TOP_BUILDDIR)/build
include $(BASE_BUILD_PATH)/Makefile.global

DESTDIR = $(CM_TOP_BUILDDIR)/output

CPPFLAGS += -I${DCC_DIRECTORY_INC}

OBJS = cm_ddb_dcc.o

all: libcmdccadapter.a libcmdccadapter.so

libcmdccadapter.so:
	$(CC) -fPIC -shared $(CXXFLAGS) $(CPPFLAGS) cm_ddb_dcc.cpp -o libcmdccadapter.so

libcmdccadapter.a: $(OBJS)
	ar crs $@ $^

clean:
	rm -rf $(OBJS) libcmdccadapter.a libcmdccadapter.so *.depend

install:all
	mkdir -p ${DESTDIR}/lib
	cp -rf ${LIB_DCC_HOME}/lib/* $(DESTDIR)/lib
	cp -rf ${LZ4_DIRECTORY_LIB}/liblz4.so* $(DESTDIR)/lib
	cp -rf ${ZSTD_DIRECTORY_LIB}/libzstd.so* $(DESTDIR)/lib
