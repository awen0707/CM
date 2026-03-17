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
 * cms_cluster_switchover.cpp
 *
 *
 * IDENTIFICATION
 *    src/cm_server/cms_cluster_switchover.cpp
 *
 * -------------------------------------------------------------------------
 */
#include "cm/cm_elog.h"
#include "alarm/alarm.h"
#include "cms_global_params.h"
#include "cms_process_messages.h"
#include "cms_cluster_switchover.h"

char switchover_flag_file_path[MAX_PATH_LEN] = {0};

void* Deal_switchover_for_init_cluster(void* arg)
{
    write_runlog(LOG, "begin do switchover for init cluster.\n");
    int cycleTime = 0;
    char command[CM_MAX_COMMAND_LEN] = {0};
    bool doSystem = false;
    int rc = 0;
    for (;;) {
        cycleTime++;
        if (access(switchover_flag_file_path, 0) != 0) {
            write_runlog(LOG, "the thread for do switchover will exit, the flag file is not exist.\n");
            break;
        }
        if (g_HA_status->local_role != CM_SERVER_PRIMARY && cycleTime <= MAX_CYCLE) {
            cm_sleep(3);
            continue;
        }
        if (cycleTime > MAX_CYCLE || isNodeBalanced(NULL) == 0) {
            write_runlog(LOG, "the thread for do switchover will exit, cycleTime is %d.\n", cycleTime);
            bool doCleanFile = true;
            for (uint32 i = 0; i < g_node_num; i++) {
                if (g_node[i].node == g_currentNode->node) {
                    rc = snprintf_s(
                        command, CM_MAX_COMMAND_LEN, CM_MAX_COMMAND_LEN - 1, "rm -rf %s", switchover_flag_file_path);
                } else {
                    rc = snprintf_s(command,
                        CM_MAX_COMMAND_LEN,
                        CM_MAX_COMMAND_LEN - 1,
                        "pssh %s -H %s \"rm -rf %s\"",
                        PSSH_TIMEOUT_OPTION,
                        g_node[i].sshChannel[0],
                        switchover_flag_file_path);
                }
                securec_check_intval(rc, (void)rc);
                rc = system(command);
                if (rc != -1 && WEXITSTATUS(rc) == 0) {
                    write_runlog(LOG, "clean switchover flag file success for ip %s.\n", g_node[i].sshChannel[0]);
                } else {
                    doCleanFile = false;
                    write_runlog(LOG,
                        "fail to clean switchover flag file for ip %s, result is %d-%d, errno=%d.\n",
                        g_node[i].sshChannel[0], rc, WEXITSTATUS(rc), errno);
                }
            }
            if (doCleanFile) {
                break;
            } else {
                cm_sleep(1);
                continue;
            }
        }
        CheckClusterStatus();
        if (!doSystem && g_HA_status->status == CM_STATUS_NORMAL && isNodeBalanced(NULL) != 0) {
            rc = system("nohup cm_ctl switchover -a > /dev/null 2>&1 &");
            if (rc == -1) {
                write_runlog(LOG, "fail to do switchover for init cluster, errno=%d.\n", errno);
            } else {
                doSystem = true;
            }
        }
        cm_sleep(3);
    }
    return NULL;
}
