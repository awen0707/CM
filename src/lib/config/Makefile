subdir = src/lib/config
CM_TOP_BUILDDIR = ../../..
BASE_BUILD_PATH = $(CM_TOP_BUILDDIR)/build
include $(CM_TOP_BUILDDIR)/build/Makefile.global

OBJS = cm_config.o

all: libconfig.a libconfig.so

libconfig.so:
	$(CC) -fPIC -shared $(CXXFLAGS) $(CPPFLAGS) cm_config.cpp -o libconfig.so

libconfig.a: $(OBJS)
	ar crs $@ $^

install:all

clean:
	rm -f $(OBJS) libconfig.a libconfig.so *.depend
