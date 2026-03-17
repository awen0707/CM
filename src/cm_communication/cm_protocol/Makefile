BASE=$(shell pwd)
CM_TOP_BUILDDIR = ../../..
BASE_BUILD_PATH = $(CM_TOP_BUILDDIR)/build
include $(BASE_BUILD_PATH)/Makefile.global
subdir = src/cm_communication/cm_protocol

include $(BASE_BUILD_PATH)/Makefile.global

DESTDIR = $(CM_TOP_BUILDDIR)/output

OBJS = $(patsubst %.cpp,%.o,$(wildcard *.cpp))

all: libcmprotocol.a libcmprotocol.so

libcmprotocol.so:
	$(CC) -fPIC -shared $(CXXFLAGS) $(CPPFLAGS) $(wildcard *.cpp) -o libcmprotocol.so

libcmprotocol.a: $(OBJS)
	ar crs $@ $^

install:all

clean:
	rm -f $(OBJS) libcmprotocol.a libcmprotocol.so *.depend
