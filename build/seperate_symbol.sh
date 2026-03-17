#!/bin/bash
# Copyright Huawei Technologies Co., Ltd. 2010-2018. All rights reserved.
set -e

function help() {
    echo ""
    echo $1
    echo ""
    echo "Usage: $0 \${FILE} \${OUT_PATH} \${EXCLUDE_OBJ} \${STRIP_MODE}"
    echo "    STRIP_MODE like: '--strip-all' or '--strip-debug'(default)"
    echo ""
}

EXCLUDE_OBJ="$3"
STRIP_MODE="--strip-debug"

function seperate_symbol() {
    local obj_name=${1}
    local out_path=${2}

    if [ -L "${obj_name}" ]; then
        echo "${obj_name} is a link, do not separate symbol!"
    elif [[ "${obj_name}" = *".py" ]]; then
        echo "${obj_name} is a script, do not separate symbol!"
    elif [[ "${obj_name}" = *".pyc" ]]; then
        echo "${obj_name} is a python cache, do not separate symbol!"
    elif [[ "${obj_name}" = *".dat" ]]; then
        echo "${obj_name} is a license file, do not separate symbol!"
    elif [[ "${obj_name}" = *".sh" ]]; then
        echo "${obj_name} is a shell file, do not separate symbol"
    elif [[ "${obj_name}" = *".conf" ]]; then
        echo "${obj_name} is a config file, do not separate symbol"
    else
        mkdir -p ${out_path}

        local obj_base_name=$(basename ${obj_name})
        local obj_name_len=$(echo ${#obj_base_name})
        set +e
        local align=$(expr ${obj_name_len} % 4)
        set -e
        local obj_symbol_name="${out_path}/${obj_base_name}"
        case ${align} in
            0)
                obj_symbol_name=${obj_symbol_name}.symbol
                ;;
            1)
                obj_symbol_name=${obj_symbol_name}000.symbol
                ;;
            2)
                obj_symbol_name=${obj_symbol_name}00.symbol
                ;;
            3)
                obj_symbol_name=${obj_symbol_name}0.symbol
                ;;
        esac

        objcopy --only-keep-debug "${obj_name}" "${obj_symbol_name}"

        objcopy ${STRIP_MODE} "${obj_name}"

        objcopy --add-gnu-debuglink="${obj_symbol_name}" "${obj_name}"

        printf '\E[33m'"\033[1mSeperate debug symbol from ${obj_name} to ${obj_symbol_name} ..... \033[0m"

        if [ -e "${obj_symbol_name}" ]; then
            echo -e '\E[32m'"\033[1mOK\033[0m"
        else
            echo -e '\E[31m'"\033[1mFAIL\033[0m"
            exit 1
        fi
    fi
}

function seperate_symbol_dir() {
    local obj_dir="${1}"
    local out_path="${2}/${obj_dir}"

    mkdir -p ${out_path}

    cd ${obj_dir}
    for o in $(ls); do
        seperate_by_file_type "${o}" "${out_path}"
    done

    # clean no symbol dir
    if [ $(ls ${out_path} | wc -l) -eq 0 ]; then
        [ -n "${out_path}" ] && rm -rf ${out_path}
    fi
    cd ..
}

function seperate_by_file_type() {
    local obj="${1}"
    local out_path="${2}"

    local obj_base_name=$(basename ${obj})
    for o in ${EXCLUDE_OBJ}; do
        if [[ "${obj_base_name}" == "$o"* ]]; then
            echo "${obj} is in exclude list, do not separate symbol"
            return 0
        fi
    done

    if [ -f "${obj}" ]; then
        seperate_symbol "${obj}" "${out_path}"
    elif [ -d "${obj}" ]; then
        seperate_symbol_dir "${obj}" "${out_path}"
    else
        echo "Unknow file type[${obj}]"
        exit 1
    fi
}

function main() {

    if [ $# -lt 3 ]; then
        help "Error : Argu must large equal 3!"
        exit 1
    fi

    if [ ! -e "${1}" ]; then
        help "File $1 not Found!"
    fi

    if [ "x$4" != "x" ]; then
        STRIP_MODE="$4"
    fi

    seperate_by_file_type "${1}" "${2}"
}

main "$@"
