#!/bin/bash
# Copyright Huawei Technologies Co., Ltd. 2010-2018. All rights reserved.
set -e

SCRIPT_PATH=$(cd $(dirname $0) && pwd)
PROJECT_ROOT_PATH=$(cd ${SCRIPT_PATH}/.. && pwd)

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
export GCC="10.3"
export PRIVATEGAUSS="ON"
export ALARM="ON"

export DCC="${PROJECT_ROOT_PATH}/../DCC"
export CBB="${PROJECT_ROOT_PATH}/../CBB"
export PKG_NAME_PRE="Package_ddes_cm"

export SYMBOLS_NAME_PRE="Symbols_ddes_cm"
export PKG_PREFIX_NAME=""
export VERSION="DEFAULT"
export USE_LSE="OFF"

function help() {
    echo "$0 [-m {release|debug|memcheck|cov}] [-3rd \${THIRD_BINARY_PATH}] [-o \${OUTPUT_PATH}] [--pkg] [--single]
        default: $0 -m ${VERSION_MODE} -3rd \"${THIRD}\" -o \"${OUT_PATH}\""
}

function build_dcc() {
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
    cd ${DCC}/../CBB/build/linux/opengauss && sh build.sh -3rd ${THIRD_BIN_PATH} -m $dcc_build_mode -t cmake
    echo "compile dcf"
    cd ${DCC}/../DCF/build/linux/opengauss && sh build.sh -3rd ${THIRD_BIN_PATH} -m $dcc_build_mode -t cmake
    echo "compile dcc"
    cd ${DCC}/build/linux/opengauss && sh build.sh -3rd ${THIRD_BIN_PATH} -m $dcc_build_mode -t cmake
    cp -rf ${DCC}/../DCF/output/lib/libdcf.so ${DCC}/output/lib
}

function clean_com_dependency() {
    local com_lib_name=$1
    echo "clean ${com_lib_name} libs[${PROJECT_ROOT_PATH}/common_lib/${com_lib_name}/]"
    mkdir -p ${PROJECT_ROOT_PATH}/common_lib/${com_lib_name}/lib
    mkdir -p ${PROJECT_ROOT_PATH}/common_lib/${com_lib_name}/include
    rm -rf ${PROJECT_ROOT_PATH}/common_lib/${com_lib_name}/lib/*
    rm -rf $PROJECT_ROOT_PATH/common_lib/${com_lib_name}/include/*
}

function update_dcc_dependency() {
    if [ -d "${DCC}" ]; then
        echo "dcc[${DCC}] found, start compile dcc!!!"
        build_dcc
        clean_com_dependency "dcc"
        cp -rf ${DCC}/src/interface/dcc_interface.h ${PROJECT_ROOT_PATH}/common_lib/dcc/include/
        cp -rf ${DCC}/output/lib/libdcc.so ${PROJECT_ROOT_PATH}/common_lib/dcc/lib/
        cp -rf ${DCC}/output/lib/libdcf.so ${PROJECT_ROOT_PATH}/common_lib/dcc/lib/
        cp -rf ${DCC}/output/lib/libgstor.so ${PROJECT_ROOT_PATH}/common_lib/dcc/lib/
        clean_com_dependency "cbb"
        local cbb_home="${THIRD_BIN_PATH}/kernel/component/cbb"
        cp -rf ${cbb_home}/include/* ${PROJECT_ROOT_PATH}/common_lib/cbb/include/
        cp -rf ${CBB}/output/lib/libcbb.a ${PROJECT_ROOT_PATH}/common_lib/cbb/lib/
        cp -rf ${CBB}/output/lib/libcbb.so ${PROJECT_ROOT_PATH}/common_lib/cbb/lib/
        cp -rf ${cbb_home}/include/cm_dlock.h ${PROJECT_ROOT_PATH}/src/cm_adapter/cm_sharedisk_adapter/
        cp -rf ${cbb_home}/include/cm_scsi.h ${PROJECT_ROOT_PATH}/src/cm_adapter/cm_sharedisk_adapter/
        cp -rf ${cbb_home}/include/cm_disklock.h ${PROJECT_ROOT_PATH}/src/cm_adapter/cm_sharedisk_adapter/
        return
    fi

    if [ "x${THIRD_BIN_PATH}" != "x" ]; then
        local dcc_home="${THIRD_BIN_PATH}/kernel/component/dcc"
        local cbb_home="${THIRD_BIN_PATH}/kernel/component/cbb"

        if [ -d "${dcc_home}" ]; then
            echo "We well get dcc lib from 3rd[${dcc_home}]."
            clean_com_dependency "dcc"
            cp -rf ${dcc_home}/include/* ${PROJECT_ROOT_PATH}/common_lib/dcc/include/
            cp -rf ${dcc_home}/lib/*.so ${PROJECT_ROOT_PATH}/common_lib/dcc/lib/
            clean_com_dependency "cbb"
            cp -rf ${cbb_home}/include/* ${PROJECT_ROOT_PATH}/common_lib/cbb/include/
            cp -rf ${cbb_home}/lib/* ${PROJECT_ROOT_PATH}/common_lib/cbb/lib/
            cp -rf ${cbb_home}/include/cm_dlock.h ${PROJECT_ROOT_PATH}/src/cm_adapter/cm_sharedisk_adapter/
            cp -rf ${cbb_home}/include/cm_scsi.h ${PROJECT_ROOT_PATH}/src/cm_adapter/cm_sharedisk_adapter/
            cp -rf ${cbb_home}/include/cm_disklock.h ${PROJECT_ROOT_PATH}/src/cm_adapter/cm_sharedisk_adapter/
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
    if [ X"${sys_tools}" = X"ON" ]; then
        export GCC_INSTALL_HOME=$(gcc -v 2>&1 | grep prefix | awk -F'prefix=' '{print $2}' |awk -F' ' '{print $1}')
    else
        export GCC_INSTALL_HOME="${THIRD}/buildtools/gcc${GCC}/gcc"
        export PATH=${GCC_INSTALL_HOME}/bin:${PATH}
    fi
    if [ ! -d "${GCC_INSTALL_HOME}" ]; then
        echo "No gcc path"
        exit 1
    fi
    export CC=$GCC_INSTALL_HOME/bin/gcc
    export CXX=$GCC_INSTALL_HOME/bin/g++
    export LD_LIBRARY_PATH=${GCC_INSTALL_HOME}/lib64:${LD_LIBRARY_PATH}
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
    cp ${PROJECT_ROOT_PATH}/tool . -R
    tar --owner=root --group=root -czf "${bin_tar}" bin lib share tool
    if [ -d symbols ]; then
        tar --owner=root --group=root -czf "${sym_tar}" symbols
    fi
}

function seperate_symbols() {
    local sep_path=${PROJECT_ROOT_PATH}/build
    local exclude_bin_objs="etcd etcdctl"
    local exclude_lib_objs="libgcc_s.so libstdc++.so"

    local strip_mode=""
    if [ "x${COMPONENT}" == "xV3" ]; then
        strip_mode="--strip-all"
    else
        strip_mode="--strip-all"
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
    if [ "${KRB}" == "OFF" ]; then
        echo "Change cms's enable_ssl value to 'ON' for KRB is not enable"
        sed -i "s/enable_ssl.*/enable_ssl = on/g" ${OUT_PATH}/share/config/cm_server.conf.sample
    fi

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
    local build_type="Release"
    local cmake_def=""
    case "${VERSION_MODE}" in
        'debug')
            build_type='Debug'
            ;;
        'release')
            build_type='Release'
            ;;
        'cov')
            build_type='Debug'
            cmake_def="-DENABLE_GCOV=ON"
            ;;
        'memcheck')
            build_type='Debug'
            cmake_def="-DENABLE_MEMCHECK=ON"
            ;;
        *)
            echo "unknown build mode, please check [-m ${VERSION_MODE}]"
            exit 1
            ;;
    esac

    if [ "${VERSION}x" != "DEFAULTx" ]; then
        echo "update version(${VERSION}) into cm.ver file."
        sed -i "s#^VERSION=.*\$#VERSION=${VERSION}#g" ${SCRIPT_PATH}/cm.ver
    fi

    PKG_NAME="${PKG_NAME_PRE}_${VERSION_MODE}.tar.gz"
    cmake_def="-DCMAKE_INSTALL_PREFIX="${OUT_PATH}" -DENABLE_PRIVATEGAUSS=${PRIVATEGAUSS} -DCMAKE_BUILD_TYPE=${build_type} ${cmake_def} -DENABLE_MULTIPLE_NODES=${MULTIPLE_NODES} -DENABLE_ETCD=${ETCD} -DENABLE_HOTPATCH=${HOTPATCH} -DENABLE_LIBPQ=${LIBPQ} -DENABLE_KRB=${KRB} -DENABLE_ALARM=${ALARM} -DUSE_LSE=${USE_LSE}"

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
    cmake_def=[${cmake_def}]
    tmp_build_dir=[${TMP_BUILD_DIR}]
    pkg_name=[${PKG_NAME}]
    version=[${VERSION}]
    lse=[${USE_LSE}]
    DCC=[${DCC}]
    output to [${OUT_PATH}]."
    echo "********************************************************************"

    mkdir -p ${TMP_BUILD_DIR}
    rm -rf ${TMP_BUILD_DIR}/*

    mkdir -p ${OUT_PATH}
    rm -rf ${OUT_PATH}/*
    cd ${TMP_BUILD_DIR}
    cmake ${cmake_def} ${PROJECT_ROOT_PATH}/

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
            -v|--version)
                if [ "$2"X = X ]; then
                    echo "no given version values."
                fi
                VERSION=$2
                shift 2
                ;;
            -dcc)
                if [ "$2"X = X ]; then
                    echo "no given DCC path values"
                    exit 1
                fi
                DCC="$2"
                CBB=${DCC}/../CBB
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
            --with_lse)
                USE_LSE="ON"
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
                echo "./build.sh --help or ./build.sh -h"
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
