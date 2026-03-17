#
CM_TOP_BUILDDIR = ../../..
BASE_BUILD_PATH = $(CM_TOP_BUILDDIR)/build
include $(BASE_BUILD_PATH)/Makefile.global
subdir = src/lib/alarm
DESTDIR = $(CM_TOP_BUILDDIR)/output

ifeq ($(ENABLE_ALARM), ON)
    OBJS = alarm.o alarm_log.o
else
    OBJS = alarm_stub.o
endif

all: libalarmclient.a

libalarmclient.a: $(OBJS)
	ar crs $@ $^

install:all
	mkdir -p $(DESTDIR)/bin
	cp -rf alarmItem.conf $(DESTDIR)/bin
	cp -rf alarmConfig.conf $(DESTDIR)/bin

clean:
	rm -f $(OBJS) libalarmclient.a *.depend
