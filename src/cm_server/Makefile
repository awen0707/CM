BASE=$(shell pwd)
CM_TOP_BUILDDIR = ../..
OPEN_CM_SRC_PATH = $(CM_TOP_BUILDDIR)/src
BASE_BUILD_PATH = $(CM_TOP_BUILDDIR)/build
COMM_LIB_PATH = $(OPEN_CM_SRC_PATH)/lib
CM_ADAPTER_PATH = $(OPEN_CM_SRC_PATH)/cm_adapter
DIST_CM_SERVER_PATH = $(DIST_PATH)/cm_server
include $(BASE_BUILD_PATH)/Makefile.global
subdir = src/cm_server

DESTDIR = $(CM_TOP_BUILDDIR)/output

ifneq ($(ENABLE_MULTIPLE_NODES)_$(ENABLE_PRIVATEGAUSS), OFF_OFF)
    LDFLAGS += -L$(DIST_PATH)/lib/hotpatch/common
    LIBS += -l:libhotpatchcommon.a
endif

ifeq ($(ENABLE_MULTIPLE_NODES), ON)
    OBJS = $(patsubst %.cpp,%.o,$(wildcard $(DIST_CM_SERVER_PATH)/*.cpp))
    LIBS += -lcgroup
endif

ifeq ($(ENABLE_KRB), ON)
    LIBS += $(addprefix -l,$(KRB_LIBS))
endif

ifeq ($(ENABLE_HOTPATCH), ON)
    LDFLAGS += -L${3RD_HOTPATCH_LIB}
    LIBS += -ldoprapatch
endif

LIBS += $(addprefix -l:,$(CM_BASE_LIBS))
LIBS += $(addprefix -l:,$(CM_ADAPTER_LIBS)) $(addprefix -l,$(DCC_LIBS))
LIBS += -l:libsecurec.a -lpthread -lcjson -lm -ldl $(addprefix -l,$(G_BIN_EXT_LIBS))

OBJS += $(SUBDIROBJS) \
	cms_alarm.o cms_conn.o cms_write_dynamic_config.o cms_process_messages.o cms_process_messages_ctl.o cms_process_messages_clt.o\
	cms_process_messages_append.o cms_process_messages_agent.o cms_sync_dynamic_info.o cms_arbitrate_cms.o cms_arbitrate_datanode_single.o \
	cms_arbitrate_datanode_psd.o cms_arbitrate_datanode_pms.o cms_monitor_main.o cms_ddb_adapter.o cms_ddb.o\
	cms_common.o cms_cluster_switchover.o cms_phony_dead_check.o cms_az.o cms_az_check_network.o cms_arbitrate_synclist.o\
	cms_global_params_utils.o cms_global_params.o cms_disk_check.o cms_threads.o cms_arbitrate_cluster.o\
	cms_main.o cms_process_messages_ctl_inter.o cms_arbitrate_datanode_pms_utils.o cms_process_messages_hadr.o cms_barrier_check.o\
	$(COMM_LIB_PATH)/config/libconfig.a\
	$(COMM_LIB_PATH)/alarm/libalarmclient.a \
	$(COMM_LIB_PATH)/hotpatch/client/libhotpatchclient.a \
	$(CM_ADAPTER_PATH)/cm_ddb_adapter/libcmddbadapter.a \
	$(CM_ADAPTER_PATH)/cm_dcc_adapter/libcmdccadapter.a \
	$(CM_ADAPTER_PATH)/cm_etcd_adapter/libcmetcdadapter.a

OBJS += $(patsubst %.cpp,%.o,$(wildcard *.cpp))

all: cm_server

cm_server: $(OBJS)
	$(CC) $(CXXFLAGS) $(LDFLAGS) $^ $(LIBS) -o $@
	$(CRC_CHECK)

install:all
	mkdir -p $(DESTDIR)/bin
	mkdir -p $(DESTDIR)/share/config
	cp -rf cm_server $(DESTDIR)/bin
	cp -rf cm_server.centralized.conf.sample $(DESTDIR)/share/config/cm_server.conf.sample

clean:
	rm -f cm_server *.o *.so
