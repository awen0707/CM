#!/bin/bash
# Copyright Huawei Technologies Co., Ltd. 2010-2018. All rights reserved.
set -e

SCRIPT_PATH=$(cd $(dirname $0) && pwd)
PROJECT_ROOT_PATH=$(cd ${SCRIPT_PATH} && pwd)

export USE_BUILD_MAKE="ON"
export COMPONENT="CM"
export VERSION_MODE="release"
export THIRD="${PROJECT_ROOT_PATH}/binarylibs"
export OUT_PATH=${PROJECT_ROOT_PATH}/output
export TMP_BUILD_DIR=${PROJECT_ROOT_PATH}/dist
export PKG="no"
export ETCD="ON"
export HOTPATCH="ON"
export MULTIPLE_NODES="ON"
export OPEN_SOURCE_MODE="inc"
export LIBPQ="ON"
export KRB="OFF"
export GCC="7.3"
export PRIVATEGAUSS="ON"
export ALARM="ON"

export DCC="${PROJECT_ROOT_PATH}/../DCC"
export PKG_NAME_PRE="Package_ddes_cm"

export SYMBOLS_NAME_PRE="Symbols_ddes_cm"
export PKG_PREFIX_NAME=""

export PROJECT_NAME="CM"
export COMMIT_ID=$(git rev-parse HEAD | cut -b 1-8)
export COMPILE_TIME=$(date "+%Y-%m-%d %H:%M:%S")

function help() {
    echo "$0 [-m {release|debug|memcheck|cov}] [-3rd \${THIRD_BINARY_PATH}] [-o \${OUTPUT_PATH}] [--pkg] [--single]
        default: $0 -m ${VERSION_MODE} -3rd \"${THIRD}\" -o \"${OUT_PATH}\""
}

function build_dcc() {
    export PLAT_FORM_STR=$(sh ${SCRIPT_PATH}/build/get_PlatForm_str.sh)
    local dcc_build_mode="Release"
    if [ $(echo $VERSION_MODE | grep -E "debug" | wc -l) -gt 0 ]; then
        dcc_build_mode="Debug"
    fi
    if [ "x${THIRD_BIN_PATH}" == "x" ]; then
        echo "THIRD_BIN_PATH not exist"
        exit 1
    fi
    echo "build dcc version mode: ${dcc_build_mode}"
    echo "compile cbb"
    cd ${DCC}/../CBB/build/linux/opengauss && sh build.sh -3rd ${THIRD_BIN_PATH} -m $dcc_build_mode -t make
    echo "compile dcf"
    cd ${DCC}/../DCF/build/linux/opengauss && sh build.sh -3rd ${THIRD_BIN_PATH} -m $dcc_build_mode -t make
    echo "compile dcc"
    cd ${DCC}/build/linux/opengauss && sh build.sh -3rd ${THIRD_BIN_PATH} -m $dcc_build_mode -t make
    cp -rf ${DCC}/../DCF/output/lib/libdcf.so ${DCC}/output/lib
}

function clean_dcc_dependency() {
    echo "clean dcc libs[${PROJECT_ROOT_PATH}/common_lib/dcc/]"
    mkdir -p ${PROJECT_ROOT_PATH}/common_lib/dcc/lib
    mkdir -p ${PROJECT_ROOT_PATH}/common_lib/dcc/include
    rm -rf ${PROJECT_ROOT_PATH}/common_lib/dcc/lib/*
    rm -rf $PROJECT_ROOT_PATH/common_lib/dcc/include/*
}

function update_dcc_dependency() {
    if [ -d "${DCC}" ]; then
        echo "dcc[${DCC}] found, start compile dcc!!!"
        build_dcc
        clean_dcc_dependency
        cp -rf ${DCC}/src/interface/dcc_interface.h ${PROJECT_ROOT_PATH}/common_lib/dcc/include/
        cp -rf ${DCC}/output/lib/libdcc.so ${PROJECT_ROOT_PATH}/common_lib/dcc/lib/
        cp -rf ${DCC}/output/lib/libdcf.so ${PROJECT_ROOT_PATH}/common_lib/dcc/lib/
        cp -rf ${DCC}/output/lib/libgstor.so ${PROJECT_ROOT_PATH}/common_lib/dcc/lib/
        return
    fi

    if [ "x${THIRD_BIN_PATH}" != "x" ]; then
        local dcc_home="${THIRD_BIN_PATH}/kernel/component/dcc"

        if [ -d "${dcc_home}" ]; then
            echo "We well get dcc lib from 3rd[${dcc_home}]."
            clean_dcc_dependency
            cp -rf ${dcc_home}/include/* ${PROJECT_ROOT_PATH}/common_lib/dcc/include/
            cp -rf ${dcc_home}/lib/*.so ${PROJECT_ROOT_PATH}/common_lib/dcc/lib/
            return
        else
            echo "***************** no dcc lib found in 3rd[${dcc_home}]!!! *******************"
        fi
    fi

    echo "there is no DCC source[${DCC}], and no 3rd path, we skip update dcc libs."
}

# use gcc7.3
function gcc_env() {
    if [ "${THIRD}" == "library" ]; then
        export CC=$(which gcc)
        export CXX=$(which g++)
        return
    fi
    export GCCFOLDER=${THIRD}/buildtools/gcc${GCC}/
    echo "gcc set to 3rd path:[${GCCFOLDER}]!"
    export CC=$GCCFOLDER/gcc/bin/gcc
    export CXX=$GCCFOLDER/gcc/bin/g++
    export LD_LIBRARY_PATH=${GCCFOLDER}/gcc/lib64:${GCCFOLDER}/isl/lib:${GCCFOLDER}/mpc/lib/:${GCCFOLDER}/mpfr/lib/:${GCCFOLDER}/gmp/lib/:$LD_LIBRARY_PATH
    export PATH=${GCCFOLDER}/gcc/bin:$PATH
}

function compile_open_source() {
    sh ${SCRIPT_PATH}/ready_open_source.sh -m ${OPEN_SOURCE_MODE} -c ${COMPONENT}
}

function cm_component_choice() {
    ETCD="OFF"
    HOTPATCH="OFF"
    MULTIPLE_NODES="OFF"
    PRIVATEGAUSS="OFF"
}

function pre_build() {
    if [ "x${COMPONENT}" != "x" ]; then
        case "${COMPONENT}" in
            'CM')
                cm_component_choice
                ;;
            *)
                echo "unknown component, please check [-c ${COMPONENT}]"
                exit 1
                ;;
        esac
    fi

    if [ "x${THIRD}" == "xlibrary" ]; then
        unset THIRD_BIN_PATH
        compile_open_source
    else
        export THIRD_BIN_PATH="${THIRD}"
        export GCC_VERSION=${GCC}
    fi

    gcc_env
}

function pkg() {
    echo "pkg cm start"
    local bin_tar="${PKG_NAME_PRE}.tar.gz"
    local sym_tar="${SYMBOLS_NAME_PRE}.tar.gz"
    if [ "x${PKG_PREFIX_NAME}" != "x" ]; then
        local bin_tar="${PKG_PREFIX_NAME}.tar.gz"
        local sym_tar="${PKG_PREFIX_NAME}-symbol.tar.gz"
    fi

    cd ${OUT_PATH}
    tar -czf "${bin_tar}" bin lib share
    if [ -d symbols ]; then
        tar -czf "${sym_tar}" symbols
    fi
}

function seperate_symbols() {
    local sep_path=${SCRIPT_PATH}/build
    local exclude_bin_objs="etcd etcdctl"
    local exclude_lib_objs="libgcc_s.so libstdc++.so"

    local strip_mode=""
    if [ "x${COMPONENT}" == "xV3" ]; then
        strip_mode="--strip-all"
    else
        strip_mode="--strip-debug"
    fi

    cd ${OUT_PATH}
    mkdir -p ${OUT_PATH}/symbols
    sh ${sep_path}/seperate_symbol.sh "bin" "${OUT_PATH}/symbols" "${exclude_bin_objs}" "${strip_mode}"
    sh ${sep_path}/seperate_symbol.sh "lib" "${OUT_PATH}/symbols" "${exclude_lib_objs}" "${strip_mode}"
    if [ "x${COMPONENT}" == "xV3" ]; then
        sh ${sep_path}/seperate_symbol.sh "cm_tools/psutil" "${OUT_PATH}/symbols" "" "${strip_mode}"
    fi
}

function after_build() {
    if [ "${VERSION_MODE}" == "release" ]; then
        seperate_symbols
    fi

    if [ "${PKG}" == "yes" ]; then
        pkg
    fi
}

function build_clean() {
    [ -d "${PROJECT_ROOT_PATH}/output" ] && rm -rf ${PROJECT_ROOT_PATH}/output/*
    [ -d "${PROJECT_ROOT_PATH}/dist" ] && rm -rf ${TMP_BUILD_DIR}/dist/*
    [ -d "${PROJECT_ROOT_PATH}/library" ] && rm -rf ${PROJECT_ROOT_PATH}/library
    echo "-- clean up --"
}

function build_cm() {
    export MAKE_BUILD_TYPE="Release"
    export MAKE_DEF=""
    case "${VERSION_MODE}" in
        'debug')
            MAKE_BUILD_TYPE='Debug'
            ;;
        'release')
            MAKE_BUILD_TYPE='Release'
            ;;
        'cov')
            MAKE_BUILD_TYPE='Debug'
            export GCOV="ON"
            ;;
        'memcheck')
            MAKE_BUILD_TYPE='Debug'
            export MEMCHECK="ON"
            ;;
        *)
            echo "unknown build mode, please check [-m ${VERSION_MODE}]"
            exit 1
            ;;
    esac

    PKG_NAME="${PKG_NAME_PRE}_${VERSION_MODE}.tar.gz"
    MAKE_DEF="MAKE_INSTALL_PREFIX="${OUT_PATH}" ENABLE_PRIVATEGAUSS=${PRIVATEGAUSS} BUILD_TYPE=${MAKE_BUILD_TYPE} ${MAKE_DEF} ENABLE_MULTIPLE_NODES=${MULTIPLE_NODES} ENABLE_ETCD=${ETCD} ENABLE_HOTPATCH=${HOTPATCH} ENABLE_LIBPQ=${LIBPQ} ENABLE_KRB=${KRB} ENABLE_ALARM=${ALARM}"
    export CM_VERSION_STR="(${PROJECT_NAME} build ${COMMIT_ID}) compiled at ${COMPILE_TIME} ${MAKE_BUILD_TYPE}"

    echo "********************************************************************"
    echo "start build CM with <${VERSION_MODE}>
    project_root_path=[${PROJECT_ROOT_PATH}]
    3rd=[${THIRD}]
    gcc=[${GCC}]
    pkg=[${PKG}]
    etcd=[${ETCD}]
    hotpatch=[${HOTPATCH}]
    libpq=[${LIBPQ}]
    krb=[${KRB}]
    multiple_nodes=[${MULTIPLE_NODES}]
    make_def=[${MAKE_DEF}]
    tmp_build_dir=[${TMP_BUILD_DIR}]
    pkg_name=[${PKG_NAME}]
    dcc=[${DCC}]
    output to [${OUT_PATH}]."
    echo "********************************************************************"

    mkdir -p ${TMP_BUILD_DIR}
    rm -rf ${TMP_BUILD_DIR}/*

    mkdir -p ${OUT_PATH}
    rm -rf ${OUT_PATH}/*
    mkdir -p ${OUT_PATH}/share/config
    mkdir -p ${OUT_PATH}/lib
    mkdir -p ${OUT_PATH}/bin

    cd ${SCRIPT_PATH}

    make clean -sj

    make install -sj
}

function main() {
    if [ "x$1" == "xclean" ]; then
        build_clean
        exit 0
    fi

    while [ $# -gt 0 ]; do
        case "$1" in
            -h | --help)
                help
                exit 1
                ;;
            -m | --version_mode)
                if [ "$2"X = X ]; then
                    echo "no given version_mode[release|debug|memcheck|cov]"
                    exit 1
                fi
                VERSION_MODE="$2"
                shift 2
                ;;
            -c | --com)
                if [ "$2"X = X ]; then
                    echo "no given Component[CM]"
                    exit 1
                fi
                COMPONENT="$2"
                shift 2
                ;;
            -o | --out_path)
                if [ "$2"X = X ]; then
                    echo "no given binarylib directory values"
                    exit 1
                fi
                OUT_PATH="$2"
                shift 2
                ;;
            -n | --pkg_name)
                if [ "$2"X = X ]; then
                    echo "no given pkg prefix name values"
                    exit 1
                fi
                PKG="yes"
                PKG_PREFIX_NAME="$2"
                shift 2
                ;;
            -3rd | --3rd_binarylib_dir)
                if [ "$2"X = X ]; then
                    echo "no given binarylib directory values"
                    exit 1
                fi
                THIRD="$2"
                shift 2
                ;;
            --gcc)
                if [ "$2"X = X ]; then
                    echo "no given gcc version values"
                    exit 1
                fi
                GCC="$2"
                shift 2
                ;;
            -dcc)
                if [ "$2"X = X ]; then
                    echo "no given DCC path values"
                    exit 1
                fi
                DCC="$2"
                shift 2
                ;;
            --pkg)
                PKG="yes"
                shift
                ;;
            --noetcd)
                ETCD="OFF"
                shift
                ;;
            --nohotpatch)
                HOTPATCH="OFF"
                shift
                ;;
            --single)
                MULTIPLE_NODES="OFF"
                shift
                ;;
            --clean)
                rm -rf ${PROJECT_ROOT_PATH}/library
                OPEN_SOURCE_MODE="all"
                shift
                ;;
            *)
                echo "Internal Error: option processing error: $1" 1>&2
                echo "./build_make.sh --help or ./build_make.sh -h"
                exit 1
                ;;
        esac
    done

    pre_build
    update_dcc_dependency
    build_cm
    after_build

    echo "ALL SUCCESS!!!!"
}

main $@
