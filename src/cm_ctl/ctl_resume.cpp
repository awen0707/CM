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
 * ctl_resume.cpp
 *    cm_ctl resume
 *                     
 *
 * IDENTIFICATION
 *    src/cm_ctl/ctl_resume.cpp
 *
 * -------------------------------------------------------------------------
 */
#include <signal.h>
#include "common/config/cm_config.h"
#include "cm/libpq-fe.h"
#include "cm/cm_misc.h"
#include "ctl_common.h"
#include "cm/cm_msg.h"
#include "cm/libpq-int.h"
#include "cm_ddb_adapter.h"
#include "ctl_common_res.h"

static status_t ResumeCluster();

extern char manual_pause_file[MAXPGPATH];
extern char hosts_path[MAXPGPATH];
extern char pssh_out_path[MAXPGPATH];
extern bool got_stop;
extern char* g_command_operation_azName;
extern uint32 g_commandOperationNodeId;

int DoResume()
{
    if (g_command_operation_azName != NULL || g_commandOperationNodeId != 0) {
        write_runlog(ERROR, "Currently, this operation can only "
            "be performed on the entire cluster.\n");
        return CM_ERROR;
    }
    init_hosts();
    if (!CheckTrustAndNet()) {
        write_runlog(ERROR, "The ssh trust relationship may be abnormal on some nodes.\n");
        return CM_ERROR;
    }
    status_t ret = ResumeCluster();
    (void)unlink(hosts_path);
    return ret;
}

static status_t ResumeCluster()
{
    if (got_stop) {
        return CM_SUCCESS;
    }

    write_runlog(LOG, "Resuming the cluster.\n");

    char command[MAXPGPATH] = {0};
    int ret = 0;
    ret = snprintf_s(command, MAXPGPATH, MAXPGPATH - 1,
        SYSTEMQUOTE "source /etc/profile;pssh -i %s -h %s \"rm %s -f\" > %s; "
                    "if [ $? -ne 0 ]; then cat %s; fi; rm -f %s"  SYSTEMQUOTE,
        PSSH_TIMEOUT_OPTION, hosts_path, manual_pause_file, pssh_out_path,
        pssh_out_path, pssh_out_path);
    securec_check_intval(ret, (void)ret);

    ret = system(command);
    if (ret != 0) {
        write_runlog(DEBUG1,
            "Failed to resume the cluster with executing the command: command=\"%s\","
            " nodeId=%u, systemReturn=%d, shellReturn=%d, errno=%d.\n",
            command, g_currentNode->node, ret, SHELL_RETURN_CODE(ret), errno);
        return CM_ERROR;
    }

    write_runlog(LOG, "The cluster has been resumed.\n");
    return CM_SUCCESS;
}
