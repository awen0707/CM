BASE=$(shell pwd)
CM_TOP_BUILDDIR = ../..
OPEN_CM_SRC_PATH = $(CM_TOP_BUILDDIR)/src
COMM_LIB_PATH = $(OPEN_CM_SRC_PATH)/lib/
CM_ADAPTER_PATH = $(OPEN_CM_SRC_PATH)/cm_adapter
BASE_BUILD_PATH = $(CM_TOP_BUILDDIR)/build
CM_AGENT_LIBPQ_PATH = $(BASE)/client_adpts/libpq
CM_AGENT_SCRIPT_PATH = $(BASE)/client_adpts/script
DIST_CM_AGENT_PATH = $(DIST_PATH)/cm_agent

include $(BASE_BUILD_PATH)/Makefile.global
subdir = src/cm_agent

DESTDIR = $(CM_TOP_BUILDDIR)/output

ifeq ($(ENABLE_MULTIPLE_NODES), ON)
    OBJS = $(patsubst %.cpp,%.o,$(wildcard $(DIST_CM_AGENT_PATH)/*.cpp))
    LIBS += -lcgroup $(addprefix -l,$(KRB_LIBS))
endif

ifeq ($(ENABLE_LIBPQ), ON)
    OBJS += $(patsubst %.cpp,%.o,$(wildcard $(CM_AGENT_LIBPQ_PATH)/*.cpp))
    CPPFLAGS += -I${OPEN_CM_SRC_PATH}/include/cm/cm_agent/clients/libpq -I$(CJSON_DIRECTORY_INC)
else
    OBJS +=$(CM_AGENT_SCRIPT_PATH)/cma_client_scripts.o
endif

ifeq ($(ENABLE_KRB), ON)
    LIBS += $(addprefix -l,$(KRB_LIBS)) -lgssrpc_gauss
endif

ifeq ($(ENABLE_MEMCHECK), ON)
    CXXFLAGS += -rdynamic
endif

LIBS += $(addprefix -l:,$(CM_BASE_LIBS))
LIBS += $(addprefix -l:,$(CM_ADAPTER_LIBS)) $(addprefix -l,$(DCC_LIBS))
LIBS += -l:libsecurec.a -lpthread -lcjson -lm -lz -ldl $(addprefix -l,$(G_BIN_EXT_LIBS))

OBJS += $(patsubst %.cpp,%.o,$(wildcard *.cpp))

all: cm_agent

cm_agent: $(OBJS)
	$(CC) $(CXXFLAGS) $(LDFLAGS) $^ $(LIBS) -o $@

install:all
	mkdir -p $(DESTDIR)/bin
	mkdir -p $(DESTDIR)/lib
	mkdir -p $(DESTDIR)/share/config
	cp -rf cm_agent $(DESTDIR)/bin
	cp -rf ${ZLIB_DIRECTORY_LIB}/libz.so* $(DESTDIR)/lib
	cp -rf cm_agent.centralized.conf.sample $(DESTDIR)/share/config/cm_agent.conf.sample

clean:
	rm -f cm_agent *.o *.so
