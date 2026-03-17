BASE=$(shell pwd)
CM_TOP_BUILDDIR = ../..
BASE_LIB_PATH = $(CM_TOP_BUILDDIR)/common_lib
PGPORT_LIB_PATH = $(BASE_LIB_PATH)/port
COMM_LIB_PATH = $(BASE_LIB_PATH)/lib
BASE_BUILD_PATH = $(CM_TOP_BUILDDIR)/build
include $(BASE_BUILD_PATH)/Makefile.global

DESTDIR = $(BASE)/../../output

VERSION = 1

include $(BASE_BUILD_PATH)/common.mk

override CFLAGS += -fstack-protector-strong -Wl,-z,relro,-z,now
override CPPFLAGS += -I. -I$(CM_TOP_BUILDDIR)/include/ -I$(CM_TOP_BUILDDIR)/include/cm -I$(CM_TOP_BUILDDIR)/include/cm/cm_adapter -I$(CM_TOP_BUILDDIR)/include/cm/cm_adapter/cm_sharedisk -I$(CM_TOP_BUILDDIR)/include/opengauss -I$(CM_TOP_BUILDDIR)/include/opengauss/cm -I$(with_3rd)/dependency/$(PLAT_FORM_STR)/etcd/comm/include/

LIBS += $(PTHREAD_LIBS)
override CPPFLAGS := $(filter-out -fPIE, $(CPPFLAGS)) -fPIC
override CFLAGS := $(filter-out -fPIE, $(CFLAGS)) -fPIC

ifneq "$(MAKECMDGOALS)" "clean"
  ifneq "$(MAKECMDGOALS)" "distclean"
    ifneq "$(shell which g++ |grep hutaf_llt |wc -l)" "1"
      -include $(DEPEND)
    endif
  endif
endif

LDFLAGS += -L$(CM_TOP_BUILDDIR)/cm_adapter/cm_sharedisk -lcmsharedisk

OBJS = cm_sd_api.o

.NOTPARALLEL:
all: libcmsdapi.a libcmsdapi.so

libcmsdapi.so:
	$(CC) -fPIC -shared $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) cm_sd_api.cpp -o libcmsdapi.so.$(VERSION)
	rm -rf libcmsdapi.so && \
	ln -sf libcmsdapi.so.$(VERSION) libcmsdapi.so

libcmsdapi.a: $(OBJS)
	$(AR) $(AROPT) $@ $^

clean:
	rm -rf $(OBJS) libcmsdapi.a libcmsdapi.so libcmsdapi.so.$(VERSION) *.depend

install: all installdirs
	$(INSTALL_STLIB) libcmsdapi.a '$(DESTDIR)$(libdir)/libcmsdapi.a'
	$(INSTALL_STLIB) libcmsdapi.so.$(VERSION) '$(DESTDIR)$(libdir)/libcmsdapi.so.$(VERSION)'
	cd '$(DESTDIR)$(libdir)' && \
	rm -f libcmsdapi.so && \
	ln -sf libcmsdapi.so.$(VERSION) libcmsdapi.so

installdirs:
	$(MKDIR_P) '$(DESTDIR)$(libdir)'

distclean:clean

uninstall:
	rm -f '$(DESTDIR)$(libdir)/libcmsdapi.a'
