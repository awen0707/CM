#----------------------------------------------------------------------------
#
# MPPDB CM ddb adapter Makefile
#
#
# distribute/cm/cm_sharedisk/Makefile
#
#-----------------------------------------------------------------------------

BASE=$(shell pwd)
CM_TOP_BUILDDIR = ../..
BASE_LIB_PATH = $(CM_TOP_BUILDDIR)/common_lib
PGPORT_LIB_PATH = $(BASE_LIB_PATH)/port
COMM_LIB_PATH = $(BASE_LIB_PATH)/lib
BASE_BUILD_PATH = $(CM_TOP_BUILDDIR)/build
include $(BASE_BUILD_PATH)/Makefile.global
subdir = cm_sharedisk

DESTDIR = $(BASE)/../../output

include $(BASE_BUILD_PATH)/common.mk

override CFLAGS += -fstack-protector-strong -Wl,-z,relro,-z,now
override CPPFLAGS += -I. -I$(CM_TOP_BUILDDIR)/include/ -I$(CM_TOP_BUILDDIR)/include/include -I$(CM_TOP_BUILDDIR)/include/cm -I$(CM_TOP_BUILDDIR)/include/opengauss -I$(CM_TOP_BUILDDIR)/include/opengauss/cm -I$(CM_TOP_BUILDDIR)/include/cm/cm_adapter/cm_sharedisk

ifneq "$(MAKECMDGOALS)" "clean"
  ifneq "$(MAKECMDGOALS)" "distclean"
    ifneq "$(shell which g++ |grep hutaf_llt |wc -l)" "1"
      -include $(DEPEND)
    endif
  endif
endif

ifeq ($(ENABLE_GCOV), ON)
    override CFLAGS += -fprofile-arcs -ftest-coverage
    override CPPFLAGS += -fprofile-arcs -ftest-coverage
    LDFLAGS += -fprofile-arcs -ftest-coverage -lgcov
endif

##############################################################################
# memory checking component
###############################################################################

ifeq ($(enable_memory_check), yes)
  LIBS += -l$(MEMCHECK_LIB_NAME_ASAN) 
  LDFLAGS += -fsanitize=address -fsanitize=leak -fno-omit-frame-pointer
  CXXFLAGS += -fsanitize=address -fsanitize=leak -fno-omit-frame-pointer
else
  ifeq ($(enable_thread_check), yes)
    LIBS += -l$(MEMCHECK_LIB_NAME_TSAN)
    LDFLAGS +=  -fsanitize=thread -fno-omit-frame-pointer
    CXXFLAGS += -fsanitize=thread -fno-omit-frame-pointer
  endif
endif

override CPPFLAGS := $(filter-out -fPIE, $(CPPFLAGS)) -fPIC
override CFLAGS := $(filter-out -fPIE, $(CFLAGS)) -fPIC

SUBDIRS = $(CM_TOP_BUILDDIR)/cm_adapter/cm_sharedisk

#LIBS := $(filter-out -ledit -lpgport -lcrypt -lssl -lrt -lbz -lddc, $(LIBS))
LIBS :=

OBJS = $(CM_TOP_BUILDDIR)/cm_common/cm_elog.o \
       	$(CM_TOP_BUILDDIR)/cm_common/be_module.o \
       	$(CM_TOP_BUILDDIR)/cm_common/cm_misc_base.o \
       	share_disk_api.o cm_disk_rw.o

.NOTPARALLEL:
all: libcmsharedisk.so cm_errcodes.h

cm_errcodes.h:$(CM_TOP_BUILDDIR)/cm_common/cm_errcodes.txt $(CM_TOP_BUILDDIR)/cm_common/generate-cm-errcodes.pl
	$(PERL) $(CM_TOP_BUILDDIR)/cm_common/generate-cm-errcodes.pl $< > $@

libcmsharedisk.so: $(OBJS)
	$(CC) -fPIC $(CPPFLAGS) $(CFLAGS) $(LIBS) -c -o $@
	$(CC) -shared $(LDFLAGS) $(OBJS) $(LIBS) -o libcmsharedisk.so

install: all installdirs
	$(INSTALL_STLIB) libcmsharedisk.so '$(DESTDIR)$(libdir)/libcmsharedisk.so'
	$(INSTALL_DATA) $(CM_TOP_BUILDDIR)/include/cm/cm_adapter/cm_sharedisk/cm_disk_rw.h '$(DESTDIR)$(includedir)/cm_disk_rw.h'

utcmsharedisk: $(OBJS)
	$(CC) -fPIC $(CPPFLAGS) $(CFLAGS) $(LIBS) -c -o $@
	$(CC) -shared $(LDFLAGS) $(OBJS) $(LIBS) -o libcmsharedisk.so
	mv libcmsharedisk.so $(CM_TOP_BUILDDIR)/test/ut/lib
	
installdirs:
	$(MKDIR_P) '$(DESTDIR)$(libdir)'
	$(MKDIR_P) '$(DESTDIR)$(includedir)'
	$(MKDIR_P) '$(DESTDIR)$(bindir)'

.PHONY: clean
clean distclean:
	rm -rf libcmsharedisk.so libcmsharedisk.so *.o *depend
	rm -rf $(CM_TOP_BUILDDIR)/include/cm/cm_errcodes.h
	rm -rf cm_errcodes.h
.PHONY: distclean
distclean:clean

uninstall:
	rm -f '$(DESTDIR)$(libdir)/libcmsharedisk.so'
