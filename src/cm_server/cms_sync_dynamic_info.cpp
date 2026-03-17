/*
 * Copyright (c) 2021 Huawei Technologies Co.,Ltd.
 *
 * CM is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 * http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 * -------------------------------------------------------------------------
 *
 * cms_sync_dynamic_info.cpp
 *
 *
 * IDENTIFICATION
 * src/cm_server/cms_sync_dynamic_info.cpp
 *
 * -------------------------------------------------------------------------
 */

#include "cms_ddb.h"
#include "cms_global_params.h"
#include "cms_write_dynamic_config.h"
#include "cms_common.h"

static bool IsCnStatusParameterValid(const char *cnId, const char *cnStatus)
{
    if (strlen(cnId) == 0 || strlen(cnStatus) == 0) {
        write_runlog(ERROR, "cnId or cnStatus is null, cnId=%s, cnStatus=%s.\n", cnId, cnStatus);
        return false;
    }
    if ((strcmp(cnStatus, "normal") != 0) && (strcmp(cnStatus, "deleted") != 0)) {
        write_runlog(ERROR, "invalid cn status:%s\n", cnStatus);
        return false;
    }
    return true;
}

static int GetReplaceCnStatusFromFile()
{
    uint32 coordinatorId = 0;
    uint32 count = 0;
    const int inputParaNum = 2;
    int cnRole = 0;
    struct stat statBuf = {0};
    const uint32 strLength = 64;
    char cnId[strLength] = {0};
    char cnStatus[strLength] = {0};
    const int bufLength = 1024;
    char buf[bufLength] = {'\0'};

    if (stat(g_replaceCnStatusFile, &statBuf) != 0) {
        write_runlog(ERROR, "file %s not exist!\n", g_replaceCnStatusFile);
        return -1;
    }

    FILE *fd = fopen(g_replaceCnStatusFile, "r");
    if (fd == NULL) {
        char errBuffer[ERROR_LIMIT_LEN] = {0};
        write_runlog(ERROR, "open cn status file %s failed! errno=%d, errmsg=%s\n", g_replaceCnStatusFile, errno,
            strerror_r(errno, errBuffer, ERROR_LIMIT_LEN));
        return -1;
    }

    while (!feof(fd)) {
        if (fgets(buf, bufLength, fd) == NULL) {
            break;
        }
        errno_t rcs = sscanf_s(buf, "%[^:]:%s", cnId, strLength, cnStatus, strLength);
        check_sscanf_s_result(rcs, inputParaNum);

        if (!IsCnStatusParameterValid(cnId, cnStatus)) {
            (void)fclose(fd);
            return -1;
        }
        coordinatorId = (uint32)strtol(cnId, NULL, 10);
        if (strcmp(cnStatus, "normal") == 0) {
            cnRole = INSTANCE_ROLE_NORMAL;
        } else if (strcmp(cnStatus, "deleted") == 0) {
            cnRole = INSTANCE_ROLE_DELETED;
        }
        write_runlog(LOG, "get replace cn status (%u:%s)\n", coordinatorId, cnStatus);

        for (uint32 i = 0; i < g_dynamic_header->relationCount; i++) {
            if (g_instance_role_group_ptr[i].instanceMember[0].instanceType == INSTANCE_TYPE_COORDINATE &&
                g_instance_role_group_ptr[i].instanceMember[0].instanceId == coordinatorId) {
                write_runlog(LOG, "get replace cn status: old status=%d, new status=%d.\n",
                    g_instance_role_group_ptr[i].instanceMember[0].role, cnRole);

                cm_instance_report_status* CnStatusForGroup = &(g_instance_group_report_status_ptr[i].instance_status);
                (void)pthread_rwlock_wrlock(&(g_instance_group_report_status_ptr[i].lk_lock));
                CnStatusForGroup->coordinatemember.cn_restart_counts = 0;
                CnStatusForGroup->command_member[0].heat_beat = 0;
                CnStatusForGroup->command_member[0].keep_heartbeat_timeout = 0;
                CnStatusForGroup->coordinatemember.auto_delete_delay_time = 0;
                if (g_instance_role_group_ptr[i].instanceMember[0].role != cnRole) {
                    g_instance_role_group_ptr[i].instanceMember[0].role = cnRole;
                }
                (void)pthread_rwlock_unlock(&(g_instance_group_report_status_ptr[i].lk_lock));
                count++;
            }
        }
    }
    (void)fclose(fd);
    write_runlog(LOG, "there are %u cn need to change status.\n", count);
    if (count == 0) {
        return -1;
    }
    return 0;
}

void SyncReplaceCnStatusToDdb()
{
    if (g_SetReplaceCnStatus == 1) {
        write_runlog(LOG, "current cmserver is primary, sync replace cn status to Ddb.\n");
        int result = GetReplaceCnStatusFromFile();
        if (result != 0) { /* the file or cn status is invalid, do nothing and return */
            g_SetReplaceCnStatus = 0;
            return;
        }

        result = SetReplaceCnStatusToDdb();
        if (result == 0) {
            (void)WriteDynamicConfigFile(false);
            g_SetReplaceCnStatus = 0;
        }
        return;
    }
}

static void GetKerberosInfoFromDdb()
{
    if (g_kerberos_check_cms_primary_standby) {
        /* kerberos: check ser ver role changed to read */
        CmsGetKerberosInfoFromDdb();
        g_kerberos_check_cms_primary_standby = false;
        write_runlog(LOG, "get kerberos info from ddb finished.\n");
    }
    return;
}

static void SyncAllDnFinishRedoFlagFromDdb()
{
    for (uint32 i = 0; i < g_dynamic_header->relationCount; i++) {
        if (g_instance_role_group_ptr[i].count > 0 &&
            g_instance_role_group_ptr[i].instanceMember[0].instanceType == INSTANCE_TYPE_DATANODE) {
            (void)pthread_rwlock_wrlock(&(g_instance_group_report_status_ptr[i].lk_lock));
            g_instance_group_report_status_ptr[i].instance_status.term = InvalidTerm;
            (void)pthread_rwlock_unlock(&(g_instance_group_report_status_ptr[i].lk_lock));

            if (!GetFinishRedoFlagFromDdb(i)) {
                (void)pthread_rwlock_wrlock(&(g_instance_group_report_status_ptr[i].lk_lock));
                g_instance_group_report_status_ptr[i].instance_status.finish_redo = false;
                (void)pthread_rwlock_unlock(&(g_instance_group_report_status_ptr[i].lk_lock));
            }
        }
    }
}

static void CmsPrimarySyncDnFinishRedoFlagFromDdb()
{
    if (g_syncDnFinishRedoFlagFromDdb) {
        if (undocumentedVersion == 0 || undocumentedVersion >= 92214) {
            (void)GetFinishRedoFlagFromDdbNew();
        } else {
            SyncAllDnFinishRedoFlagFromDdb();
        }
        g_syncDnFinishRedoFlagFromDdb = false;
        write_runlog(LOG, "Sync DN finish redo flag from Ddb when cms promte to primary.\n");
    }
    return;
}

void* SyncDynamicInfoFromDdb(void* arg)
{
    uint32 i = 0;
    thread_name = "SYNC";
    if (!IsNeedSyncDdb()) {
        write_runlog(LOG, "We don't need SYNC thread, exit.\n");
        return NULL;
    }
    for (;;) {
        if (got_stop == 1) {
            break;
        }

        if (g_multi_az_cluster) {
            cm_server_start_mode = get_cm_start_mode(minority_az_start_file);
        }

        if (IsDdbHealth(DDB_PRE_CONN)) {
            write_runlog(DEBUG1, "will sync instance info from ddb. \n");
            CmsSyncStandbyMode();
            if ((cm_arbitration_mode == MINORITY_ARBITRATION || cm_server_start_mode == MINORITY_START) &&
                g_multi_az_cluster) {
                write_runlog(LOG,
                    "SyncDynamicInfoFromDdb, current node(%u) in minority, we should sync CN status to ddb.\n",
                    g_currentNode->node);
                if (SetReplaceCnStatusToDdb() != 0) {
                    write_runlog(ERROR, "Sync CN status to ddb failed.\n");
                }
                cm_sleep(1);
                continue;
            }

            SyncReplaceCnStatusToDdb();
            GetKerberosInfoFromDdb();
            CmsPrimarySyncDnFinishRedoFlagFromDdb();
            if (undocumentedVersion == 0 || undocumentedVersion >= 92214) {
                GetCoordinatorDynamicConfigChangeFromDdbNew(0);
                if (g_multi_az_cluster) {
                    GetDatanodeDynamicConfigChangeFromDdbNew(0);
                }

                for (i = 0; i < g_dynamic_header->relationCount; i++) {
                    GetGtmDynamicConfigChangeFromDdb(i);
                    if (!g_multi_az_cluster) {
                        GetDatanodeDynamicConfigChangeFromDdb(i);
                    }
                }
            } else {
                for (i = 0; i < g_dynamic_header->relationCount; i++) {
                    GetGtmDynamicConfigChangeFromDdb(i);
                    GetDatanodeDynamicConfigChangeFromDdb(i);
                    GetCoordinatorDynamicConfigChangeFromDdb(i);
                }
            }
            write_runlog(DEBUG1, "sync instance info from Ddb end. \n");
        }
        cm_sleep(1);
    }
    return NULL;
}

