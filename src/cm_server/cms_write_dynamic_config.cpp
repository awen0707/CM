/*
 * Copyright (c) 2021 Huawei Technologies Co.,Ltd.
 *
 * CM is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *          http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 * -------------------------------------------------------------------------
 *
 * cms_write_dynamic_config.cpp
 *
 *
 * IDENTIFICATION
 *    src/cm_server/cms_write_dynamic_config.cpp
 *
 * -------------------------------------------------------------------------
 */
#include "cms_write_dynamic_config.h"
#include "cms_global_params.h"
#include "cms_ddb_adapter.h"

/**
 * @brief
 *  only add g_refreshDynamicCfgNum if isRealWriteDynamic is false,
    write dynaminc file will be done by WriteDynamicCfg thread
 *
 * @note
 *  if not WriteDynamicCfgMain thread call this function, isRealWriteDynamic input can be false
 *
 * @param  isRealWriteDynamic .
 * @return Return the write result.
 */
int WriteDynamicConfigFile(bool isRealWriteDynamic)
{
    if (!isRealWriteDynamic && NeedCreateWriteDynamicThread()) {
        (void)pthread_rwlock_wrlock(&dynamic_file_rwlock);
        ++g_refreshDynamicCfgNum;
        (void)pthread_rwlock_unlock(&dynamic_file_rwlock);
        return 0;
    }
    
    size_t headerSize = sizeof(dynamicConfigHeader);
    size_t headerAglinmentSize =
        (headerSize / AGLINMENT_SIZE + ((headerSize % AGLINMENT_SIZE == 0) ? 0 : 1)) * AGLINMENT_SIZE;
    size_t cmsStateTimelineSize = sizeof(dynamic_cms_timeline);

    (void)pthread_rwlock_wrlock(&dynamic_file_rwlock);

    int fd = open(cm_dynamic_configure_path, O_RDWR | O_CLOEXEC, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        char errBuffer[ERROR_LIMIT_LEN];
        write_runlog(ERROR, "WriteDynamicConfigFile open file:errno=%d, errmsg=%s\n",
            errno, strerror_r(errno, errBuffer, ERROR_LIMIT_LEN));
        (void)pthread_rwlock_unlock(&dynamic_file_rwlock);
        return -1;
    }
    ssize_t returnCode = write(fd, g_dynamic_header, headerAglinmentSize + cmsStateTimelineSize +
            (g_dynamic_header->relationCount) * sizeof(cm_instance_role_group));
    if (returnCode != (ssize_t)(headerAglinmentSize + cmsStateTimelineSize +
        (g_dynamic_header->relationCount) * sizeof(cm_instance_role_group))) {
        char errBuffer[ERROR_LIMIT_LEN];
        write_runlog(ERROR, "WriteDynamicConfigFile write file with dynamic instance role group "
            "configuration info failed, errno=%d, errmsg=%s\n", errno, strerror_r(errno, errBuffer, ERROR_LIMIT_LEN));
        (void)close(fd);
        (void)pthread_rwlock_unlock(&dynamic_file_rwlock);
        return -1;
    }
    int ret = fsync(fd);
    if (ret != 0) {
        char errBuffer[ERROR_LIMIT_LEN];
        write_runlog(ERROR, "WriteDynamicConfigFile fsync file failed, errno=%d, errmsg=%s\n",
            errno, strerror_r(errno, errBuffer, ERROR_LIMIT_LEN));
        (void)close(fd);
        (void)pthread_rwlock_unlock(&dynamic_file_rwlock);
        return -1;
    }
    (void)close(fd);
    (void)pthread_rwlock_unlock(&dynamic_file_rwlock);
    return 0;
}

bool NeedCreateWriteDynamicThread()
{
    return g_multi_az_cluster && IsNeedSyncDdb();
}

void* WriteDynamicCfgMain(void* arg)
{
    static uint32 lastRefreshDynamicCfgNum = 0;

    while (true) {
        if (got_stop == 1) {
            break;
        }

        (void)pthread_rwlock_wrlock(&dynamic_file_rwlock);
        if (lastRefreshDynamicCfgNum != g_refreshDynamicCfgNum) {
            lastRefreshDynamicCfgNum = g_refreshDynamicCfgNum;
            (void)pthread_rwlock_unlock(&dynamic_file_rwlock);
            (void)WriteDynamicConfigFile(true);

            write_runlog(DEBUG1,
                "Begin to write dynamic config file [%u,%u].\n",
                lastRefreshDynamicCfgNum,
                g_refreshDynamicCfgNum);
        } else {
            (void)pthread_rwlock_unlock(&dynamic_file_rwlock);
        }
        cm_sleep(1);
    }

    return NULL;
}
