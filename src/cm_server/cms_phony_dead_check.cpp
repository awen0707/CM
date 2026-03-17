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
 * cms_phony_dead_check.cpp
 *
 *
 * IDENTIFICATION
 *    src/cm_server/cms_phony_dead_check.cpp
 *
 * -------------------------------------------------------------------------
 */

#include "cm/cm_elog.h"
#include "cms_alarm.h"
#include "cms_global_params.h"
#include "cms_phony_dead_check.h"

void *deal_phony_dead_alarm(void *arg)
{
    int rc = 0;
    char instanceName[CM_NODE_NAME] = {0};
    for (;;) {
        if (g_HA_status->local_role != CM_SERVER_PRIMARY) {
            cm_sleep(20);
            continue;
        }

        for (uint32 i = 0; i < g_dynamic_header->relationCount; i++) {
            for (int32 j = 0; j < g_instance_role_group_ptr[i].count; j++) {
                if ((g_instance_role_group_ptr[i].instanceMember[j].instanceType == INSTANCE_TYPE_DATANODE) &&
                    g_instance_group_report_status_ptr[i].instance_status.data_node_member[j].phony_dead_times <
                    phony_dead_effective_time) {
                    rc = snprintf_s(instanceName, sizeof(instanceName), sizeof(instanceName) - 1, "dn_%u",
                        g_instance_role_group_ptr[i].instanceMember[j].instanceId);
                    securec_check_intval(rc, (void)rc);
                } else if ((g_instance_role_group_ptr[i].instanceMember[j].instanceType == INSTANCE_TYPE_GTM) &&
                    g_instance_group_report_status_ptr[i].instance_status.gtm_member[j].phony_dead_times <
                    phony_dead_effective_time) {
                    rc = snprintf_s(instanceName, sizeof(instanceName), sizeof(instanceName) - 1, "gtm_%u",
                        g_instance_role_group_ptr[i].instanceMember[j].instanceId);
                    securec_check_intval(rc, (void)rc);
                } else if ((g_instance_role_group_ptr[i].instanceMember[j].instanceType == INSTANCE_TYPE_COORDINATE) &&
                    g_instance_group_report_status_ptr[i].instance_status.coordinatemember.phony_dead_times <
                    phony_dead_effective_time) {
                    rc = snprintf_s(instanceName, sizeof(instanceName), sizeof(instanceName) - 1, "cn_%u",
                        g_instance_role_group_ptr[i].instanceMember[j].instanceId);
                    securec_check_intval(rc, (void)rc);
                }
                report_phony_dead_alarm(ALM_AT_Resume, instanceName,
                    g_instance_role_group_ptr[i].instanceMember[j].instanceId);
            }
        }

        cm_sleep(20);
        continue;
    }
}
void DealDNPhonyDeadStatusE2E(uint32 groupIndex, int memberIndex)
{
    char instanceName[CM_NODE_NAME] = {0};
    int rc = 0;
    const int phonyDeadEffectiveTime = 2;
    if (g_instance_group_report_status_ptr[groupIndex].instance_status.data_node_member[memberIndex].phony_dead_times >=
        phonyDeadEffectiveTime) {
        rc = snprintf_s(instanceName, sizeof(instanceName), sizeof(instanceName) - 1, "dn_%u",
            g_instance_role_group_ptr[groupIndex].instanceMember[memberIndex].instanceId);
        securec_check_intval(rc, (void)rc);
        report_phony_dead_alarm(ALM_AT_Fault, instanceName,
            g_instance_role_group_ptr[groupIndex].instanceMember[memberIndex].instanceId);
        const uint32 maxArbitrateInterval = 100;
        int count = g_instance_role_group_ptr[groupIndex].count;
        for (int i = 0; i < count; ++i) {
            g_instance_group_report_status_ptr[groupIndex].instance_status.data_node_member[i].arbiTime +=
                maxArbitrateInterval;
        }
        write_runlog(LOG, "datanode phony dead arbitrate time is : %u, dn_%u, local_arbitrate_time=%u.\n",
            g_instance_group_report_status_ptr[groupIndex].instance_status.time,
            g_instance_role_group_ptr[groupIndex].instanceMember[memberIndex].instanceId,
            g_instance_group_report_status_ptr[groupIndex].instance_status.data_node_member[memberIndex].arbiTime);
    }
    return;
}

void DealGTMPhonyDeadStatusE2E(uint32 groupIndex, int memberIndex)
{
    char instanceName[CM_NODE_NAME] = {0};
    int rc = 0;
    if (g_instance_group_report_status_ptr[groupIndex].instance_status.gtm_member[memberIndex].phony_dead_times >=
        phony_dead_effective_time) {
        rc = snprintf_s(instanceName, sizeof(instanceName), sizeof(instanceName) - 1, "gtm_%u",
            g_instance_role_group_ptr[groupIndex].instanceMember[memberIndex].instanceId);
        securec_check_intval(rc, (void)rc);
        report_phony_dead_alarm(ALM_AT_Fault, instanceName,
            g_instance_role_group_ptr[groupIndex].instanceMember[memberIndex].instanceId);
        write_runlog(LOG, "gtm phony dead set local_role Unknown, gtm_%u, phony_dead_times=%d.\n",
            g_instance_role_group_ptr[groupIndex].instanceMember[memberIndex].instanceId,
            g_instance_group_report_status_ptr[groupIndex].instance_status.gtm_member[memberIndex].phony_dead_times);
    }
    return;
}

void DealCNPhonyDeadStatusE2E(uint32 groupIndex, int memberIndex)
{
    char instanceName[CM_NODE_NAME] = {0};
    int rc = 0;
    if (g_instance_group_report_status_ptr[groupIndex].instance_status.coordinatemember.phony_dead_times >=
        phony_dead_effective_time) {
        rc = snprintf_s(instanceName, sizeof(instanceName), sizeof(instanceName) - 1, "cn_%u",
            g_instance_role_group_ptr[groupIndex].instanceMember[memberIndex].instanceId);
        securec_check_intval(rc, (void)rc);
        report_phony_dead_alarm(ALM_AT_Fault, instanceName,
            g_instance_role_group_ptr[groupIndex].instanceMember[memberIndex].instanceId);

        write_runlog(LOG, "cn phony dead cn_%u, phony_dead_times=%d.\n",
            g_instance_role_group_ptr[groupIndex].instanceMember[memberIndex].instanceId,
            g_instance_group_report_status_ptr[groupIndex].instance_status.coordinatemember.phony_dead_times);
    }
}
