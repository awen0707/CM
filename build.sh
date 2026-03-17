#!/bin/bash
# Copyright Huawei Technologies Co., Ltd. 2010-2018. All rights reserved.
set -e

SCRIPT_PATH=$(cd $(dirname $0) && pwd)

# which default opt if not pointed
DEFAULT_OPT="-o ${SCRIPT_PATH}/output"

# which must choose
FIX_OPT="-c CM"

sh ${SCRIPT_PATH}/build/build.sh ${DEFAULT_OPT} "$@" ${FIX_OPT}
