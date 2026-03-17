CM_TOP_BUILDDIR = .
include $(CM_TOP_BUILDDIR)/build/Makefile.global

ifndef CM_VERSION_STR
    PROJECT_NAME = CM
    COMMIT_ID = $(shell git rev-parse HEAD | cut -b 1-8)
    COMPILE_TIME = $(shell date "+%Y-%m-%d %H:%M:%S")
    export CM_VERSION_STR = ($(PROJECT_NAME) build $(COMMIT_ID)) compiled at $(COMPILE_TIME) $(BUILD_TYPE)
    $(info CM_VERSION_STR=$(CM_VERSION_STR))
endif

SUBDIRS = src

$(recurse)
