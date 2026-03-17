BASE=$(shell pwd)
subdir = src/cm_ctl

BASE=$(shell pwd)
CM_TOP_BUILDDIR = ../..
OPEN_CM_SRC_PATH = $(CM_TOP_BUILDDIR)/src
BASE_BUILD_PATH = $(CM_TOP_BUILDDIR)/build
CM_ADAPTER_PATH = $(OPEN_CM_SRC_PATH)/cm_adapter
COMM_LIB_PATH = $(OPEN_CM_SRC_PATH)/lib
DESTDIR = $(CM_TOP_BUILDDIR)/output

include $(BASE_BUILD_PATH)/Makefile.global

OBJS = $(patsubst %.cpp,%.o,$(wildcard *.cpp)) $(COMM_LIB_PATH)/pq/port/cipher.o $(OPEN_CM_SRC_PATH)/cm_communication/cm_libpq/pqsignal.o

LIBS += $(addprefix -l:,$(CM_BASE_LIBS))
LIBS += $(addprefix -l:,$(CM_ADAPTER_LIBS)) $(addprefix -l,$(DCC_LIBS))
LIBS += -l:libsecurec.a -lpthread -lcjson -lm $(addprefix -l,$(G_BIN_EXT_LIBS))

ifeq ($(ENABLE_MULTIPLE_NODES), ON)
    OBJS += $(CM_TOP_BUILDDIR)/distribute/cm_ctl/ctl_distribute.o
    LIBS += -lcgroup
endif

ifeq ($(ENABLE_KRB), ON)
    LIBS += $(addprefix -l,$(KRB_LIBS)) -lgssrpc_gauss
endif


all: cm_ctl

cm_ctl: $(OBJS)
	$(CC) $(CXXFLAGS) $(LDFLAGS) $^ $(LIBS) -o $@

install:all
	mkdir -p $(DESTDIR)/bin
	cp -rf cm_ctl $(DESTDIR)/bin

clean:
	rm -f cm_ctl *.o
