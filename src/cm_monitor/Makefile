BASE=$(shell pwd)
CM_TOP_BUILDDIR = ../..
OPEN_CM_SRC_PATH = $(CM_TOP_BUILDDIR)/src
COMM_LIB_PATH = $(OPEN_CM_SRC_PATH)/lib/
CM_ADAPTER_PATH = $(OPEN_CM_SRC_PATH)/cm_adapter


BASE_BUILD_PATH = $(CM_TOP_BUILDDIR)/build
include $(BASE_BUILD_PATH)/Makefile.global
subdir = src/cm_monitor

DESTDIR = $(CM_TOP_BUILDDIR)/output

OBJS = $(patsubst %.cpp,%.o,$(wildcard *.cpp))

LIBS += $(addprefix -l:,$(CM_BASE_LIBS))
LIBS += -l:libsecurec.a -lcjson -lcrypt -ldl -lm -lssl -lcrypto -lpthread -lrt $(addprefix -l,$(G_BIN_EXT_LIBS))

ifeq ($(ENABLE_MULTIPLE_NODES), ON)
    LIBS += -lcgroup
endif

ifeq ($(ENABLE_KRB), ON)
    LIBS += $(addprefix -l, $(KRB_LIBS))
endif


all: om_monitor

om_monitor: $(OBJS)
	$(CC) $(CXXFLAGS) $(LDFLAGS) $^ $(LIBS) -o $@

install:all
	mkdir -p $(DESTDIR)/bin
	cp -rf om_monitor $(DESTDIR)/bin

clean:
	rm -f om_monitor *.o