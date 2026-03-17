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
 * ctl_help.cpp
 *
 *
 * IDENTIFICATION
 *    src/cm_ctl/ctl_help.cpp
 *
 * -------------------------------------------------------------------------
 */
#include "c.h"

static void StartUsage(const char *projectName)
{
#ifdef ENABLE_MULTIPLE_NODES
    (void)printf(_("  %s start [[-z AVAILABILITY_ZONE [--cm_arbitration_mode=ARBITRATION_MODE]] | "
                   "[-n NODEID [-D DATADIR [-R] | -I RESOURCE_INSTANCE_ID]] | [-m resume]] [-t SECS] \n"),
        projectName);
#else
    (void)printf(_("  %s start [-z AVAILABILITY_ZONE [--cm_arbitration_mode=ARBITRATION_MODE]] | "
                   "[-n NODEID [-D DATADIR]] | [-I RESOURCE_INSTANCE_ID [-n NODEID]] [-t SECS] \n"),
        projectName);
#endif
}

static void SwitchoverUsage(const char *projectName)
{
#ifdef ENABLE_MULTIPLE_NODES
    (void)printf(
        _("  %s switchover [-z AVAILABILITY_ZONE] | [-n NODEID -D DATADIR [-q] | [-f]] | [-a [-q]] | [-A] [-t SECS]\n"),
        projectName);
#else
    (void)printf(_("  %s switchover [-z AVAILABILITY_ZONE] | [-n NODEID -D DATADIR [-f]] | [-a] | [-A] [-t SECS]\n"),
        projectName);
#endif
}

static void UsageHelp(const char *projectName)
{
    (void)printf(_("Usage:\n"));
    StartUsage(projectName);
    SwitchoverUsage(projectName);
#ifdef ENABLE_LIBPQ
    (void)printf(_("  %s finishredo\n"), projectName);
#endif
    (void)printf(_("  %s build [-c] [-n NODEID] [-D DATADIR [-t SECS] [-f] [-b full] [-j NUM]]\n"), projectName);
    (void)printf(_("  %s check -B BINNAME -T DATAPATH\n"), projectName);
#ifdef ENABLE_MULTIPLE_NODES
    (void)printf(_("  %s stop [[-z AVAILABILITY_ZONE] | [-n NODEID [-D DATADIR [-R] | -I RESOURCE_INSTANCE_ID]]] "
        "[-t SECS] [-m SHUTDOWN-MODE]\n"), projectName);
    (void)printf(_("  %s query [-z ALL] [-n NODEID [-D DATADIR -R]] [-l FILENAME] [-v [-C [-w] [-s] [-S] [-d] [-i] [-F] "
        "[-L ALL] [-x] [-p]] | [-r]] [-t SECS] [--minorityAz=AZ_NAME]\n"), projectName);
    (void)printf(_("  %s restart [-L LCNAME]\n"), projectName);
    (void)printf(_("  %s view [-v | -N | -n NODEID | -c] [-l FILENAME]\n"), projectName);
    (void)printf(_("  %s disable -n NODEID -D DATADIR [-t SECS]\n"), projectName);
#else
    (void)printf(_("  %s stop [[-z AVAILABILITY_ZONE] | [-n NODEID [-D DATADIR]] | [-I RESOURCE_INSTANCE_ID [-n NODEID]]] [-t SECS] "
        "[-m SHUTDOWN-MODE]\n"), projectName);
    (void)printf(_("  %s query [-z ALL] [-l FILENAME] [-v [-C [-w] [-s] [-S] [-d] [-i] [-F] [-x] [-p]] | [-r]] [-t SECS] "
        "[--minorityAz=AZ_NAME]\n"), projectName);
    (void)printf(_("  %s view [-v | -N | -n NODEID] [-l FILENAME]\n"), projectName);
#endif
    (void)printf(_("  %s set [--log_level=LOG_LEVEL] [--cm_arbitration_mode=ARBITRATION_MODE] "
                   "[--cm_switchover_az_mode=SWITCHOVER_AZ_MODE] [--cmsPromoteMode=CMS_PROMOTE_MODE -I INSTANCEID]\n"),
        projectName);
    (void)printf(_("  %s set --param --agent | --server [-n NODEID] -k [PARAMETER]=\"[value]\"\n"), projectName);
    (void)printf(_("  %s get [--log_level] [--cm_arbitration_mode] [--cm_switchover_az_mode]\n"), projectName);
#if defined(ENABLE_MULTIPLE_NODES) || defined(ENABLE_PRIVATEGAUSS)
    (void)printf(_("  %s hotpatch -E PATCH_COMMAND -P PATCH_NAME\n"), projectName);
#endif
#ifdef ENABLE_LIBPQ
    (void)printf(_("  %s setrunmode -n NODEID -D DATADIR  "
        "[[--xmode=normal] | [--xmode=minority --votenum=NUM]]\n"), projectName);
    (void)printf(_("  %s changerole [--role=PASSIVE | --role=FOLLOWER] -n NODEID -D DATADIR [-t SECS]\n"), projectName);
    (void)printf(_("  %s changemember [--role=PASSIVE | --role=FOLLOWER] [--group=xx] [--priority=xx] "
        "-n NODEID -D DATADIR [-t SECS]\n"), projectName);
#endif
    (void)printf(_("  %s reload --param --agent | --server [-n NODEID]\n"), projectName);
    (void)printf(_("  %s list --param --agent | --server [-n NODEID]\n"), projectName);
    (void)printf(_("  %s encrypt [-M MODE] -D DATADIR\n"), projectName);
    (void)printf(_("  %s ddb DDB_CMD\n"), projectName);
    (void)printf(_("  %s switch [--ddb_type=[DDB]] [--commit] [--rollback]\n"), projectName);
    (void)printf(_("  %s res {--add --res_name=\"NAME\" --res_attr=\"RES_INFO\" | "
        "--del --res_name=\"NAME\" | --edit --res_name=\"NAME\" | --list {--res_name=\"NAME\"} "
        "{--res_attr=\"RES_INFO\" | --add_inst=\"INST_INFO\" | --del_inst=\"INST_INFO\" | --edit_inst=\"INST_INFO\" "
        "{--inst_attr=\"INST_ATTR\"} | --list_inst} | --check }\n"), projectName);
    (void)printf(_("  %s show\n"), projectName);
    (void)printf(_("  %s pause\n"), projectName);
    (void)printf(_("  %s resume\n"), projectName);
}

static void CommonHelp()
{
    (void)printf(_("\nCommon options:\n"));
    (void)printf(_("  -D DATADIR             location of the database storage area\n"));
    (void)printf(_("  -l FILENAME            write (or append) result to FILENAME\n"));
    (void)printf(_("  -n NODEID              node id\n"));
    (void)printf(_("  -z AVAILABILITY_ZONE   availability zone name\n"));
    (void)printf(_("  -t SECS                seconds to wait\n"));
#ifdef ENABLE_MULTIPLE_NODES
    (void)printf(_("  -R                     the flag that only relation datanodes are processed.\n"));
#endif
    (void)printf(_("  -V, --version          output version information, then exit\n"));
    (void)printf(_("  -?, -h, --help         show this help, then exit\n"));
}

static void SwitchoverHelp()
{
    (void)printf(_("\nOptions for switchover:\n"));
#ifdef ENABLE_MULTIPLE_NODES
    (void)printf(_("  -a                     auto switchover to rebalance mppdb cluster\n"));
    (void)printf(_("  -q                     quick switchover GTM/DN instances\n"));
    (void)printf(_("  -a -q                  auto quick switchover to rebalance mppdb cluster, not applicable for "
                   "one-primary-multi-standby cluster mode\n"));
    (void)printf(
        _("  -A                     switch all the GTM and DN's standby instances with their master instances\n"));
#else
    (void)printf(_("  -a                     auto switchover to rebalance mppdb service\n"));
    (void)printf(
        _("  -A                     switch all the datanode's standby instances with their master instances\n"));
#endif
    (void)printf(_("  -f                     fast switchover\n"));
}

static void BuildHelp()
{
    (void)printf(_("\nOptions for build:\n"));
    (void)printf(_("  -f                     force build\n"));
    (void)printf(_("  -b full                full build\n"));
    (void)printf(_("  -c                     cm server build\n"));
    (void)printf(_("  -j [num]               parallelism\n"));
}

static void CheckHelp()
{
    (void)printf(_("\nOptions for check:\n"));
#ifdef ENABLE_MULTIPLE_NODES
    (void)printf(_("  -B BINNAME             BINNAME can be \"cm_agent\", \"gs_gtm\", \"gaussdb\" or \"cm_server\"\n"));
#else
#ifdef ENABLE_LIBPQ
    (void)printf(_("  -B BINNAME             BINNAME can be \"cm_agent\", \"gaussdb\" or \"cm_server\"\n"));
#else
    (void)printf(_("  -B BINNAME             BINNAME can be \"cm_agent\", \"zengine\" or \"cm_server\"\n"));
#endif
#endif
    (void)printf(_("  -T DATAPATH            location of the database storage area\n"));
}

static void StartAndStopHelp()
{
    (void)printf(_("\nOptions for start:\n"));
#ifdef ENABLE_MULTIPLE_NODES
    (void)printf(_("  -m resume              enable resuming the fault CN\n"));
#endif
    (void)printf(_("  -I INSTANCE_ID         start one resource instance.\n"));

    (void)printf(_("\nOptions for stop:\n"));
#ifdef ENABLE_MULTIPLE_NODES
    (void)printf(_("  -m MODE                MODE can be \"smart\" \"fast\" \"immediate\", or \"resume\"\n"));
#else
    (void)printf(_("  -m MODE                MODE can be \"smart\" \"fast\" \"immediate\"\n"));
#endif
    (void)printf(_("  -I INSTANCE_ID         stop one resource instance.\n"));
}

static void QueryHelp()
{
    (void)printf(_("\nOptions for query:\n"));
    (void)printf(_("  -s                     show instances that need to switchover\n"));
    (void)printf(_("  -C                     show query result by HA relation\n"));
    (void)printf(_("  -v                     show detail query result\n"));
    (void)printf(_("  -w                     show detail query result in vertical format\n"));
    (void)printf(_("  -d                     show instance datapath\n"));
    (void)printf(_("  -i                     show physical node ip\n"));
    (void)printf(_("  -F                     show all fenced UDF master process status\n"));
#ifdef ENABLE_MULTIPLE_NODES
    (void)printf(_("  -L ALL                 show logic cluster status\n"));
#endif
    (void)printf(_("  -z                     show all availability zone status. The value must be \"ALL\"\n"));
    (void)printf(_("  -r                     show standby DN redo status\n"));
    (void)printf(_("  -g                     show backup and recovery cluster info\n"));
    (void)printf(_("  -x                     show abnormal instances\n"));
    (void)printf(_("  -S                     show the results of the status check when the cluster was started\n"));
#if ((defined(ENABLE_MULTIPLE_NODES)) || (defined(ENABLE_PRIVATEGAUSS)))
    (void)printf(_("  --minorityAz           check the cms, etcd status only in the pointed AZ\n"));
#else
    (void)printf(_("  --minorityAz           check the cms status only in the pointed AZ\n"));
#endif

#ifdef ENABLE_MULTIPLE_NODES
    (void)printf(
        _("  -p                     show the port of coordinator and datanode, without dummy standby and central "
          "coordinator\n"));
#else
    (void)printf(_("  -p                     show the port of datanode\n"));
#endif
}

#ifdef ENABLE_MULTIPLE_NODES
static void RestartHelp()
{
    (void)printf(_("\nOptions for restart:\n"));
    (void)printf(_("  -L LCNAME              restart the logic cluster,LCNAME is the logic cluster name\n"));
}
#endif

static void SetAndGetHelp()
{
    (void)printf(_("\nOptions for set:\n"));
    (void)printf(_("  --log_level=LOG_LEVEL                           LOG_LEVEL can be \"DEBUG5\", \"DEBUG1\", \"LOG\","
                   " \"WARNING\", \"ERROR\" or \"FATAL\"\n"));
    (void)printf(
        _("  --cm_arbitration_mode=ARBITRATION_MODE          ARBITRATION_MODE can be \"MAJORITY\", \"MINORITY\"\n"));
    (void)printf(
        _("  --cm_switchover_az_mode= SWITCHOVER_AZ_MODE     SWITCHOVER_AZ_MODE can be \"NON_AUTO\", \"AUTO\"\n"));
    (void)printf(
        _("  --cmsPromoteMode=CMS_PROMOTE_MODE -I INSTANCEID CMS_PROMOTE_MODE can be \"AUTO\", \"PRIMARY_F\"\n"));
    (void)printf(_("  --param                set conf param\n"));
    (void)printf(_("  --agent                set cm agent conf\n"));
    (void)printf(_("  --server               set cm server conf\n"));
    (void)printf(_("  --k                    set parameter and value \n"));

    (void)printf(_("\nOptions for get:\n"));
    (void)printf(_("  --log_level              show LOG_LEVEL\n"));
    (void)printf(_("  --cm_arbitration_mode    show cm server arbitration mode\n"));
    (void)printf(_("  --cm_switchover_az_mode  show az switchover mode\n"));
}

static void OptionsForView()
{
    (void)printf(_("\nOptions for view:\n"));
    (void)printf(_("  -v                     show details of static config\n"));
    (void)printf(_("  -N                     show local node static config\n"));
#ifdef ENABLE_MULTIPLE_NODES
    (void)printf(_("  -c                     show coordinator dynamic config\n"));
#endif
}


#if defined(ENABLE_MULTIPLE_NODES) || defined(ENABLE_PRIVATEGAUSS)
static void OptionsForHotpatch()
{
    (void)printf(_("\nOptions for hotpatch:\n"));
    (void)printf(_("  -E PATCH_COMMAND       patch command, PATCH_COMMAND can be"
                   "\"load\" \"unload\" \"active\" \"deactive\" \"info\" \"list\"\n"));
    (void)printf(_("  -P PATCH_NAME          patch name, PATCH_NAME should be patch name with path\n"));
}
#endif

static void ShutdownModeHelp()
{
    (void)printf(_("\nShutdown modes are:\n"));
    (void)printf(_("  smart                  quit with fast shutdown on primary, and recovery done on standby\n"));
    (void)printf(_("  fast                   quit directly, with proper shutdown\n"));
    (void)printf(_("  immediate              quit without complete shutdown; will lead to recovery on restart\n"));
#ifdef ENABLE_MULTIPLE_NODES
    (void)printf(
        _("  resume                 quit if the fault CN is being resumed: stop building CN and unlock DDL\n"));
#endif
}

static void StatusHelp()
{
    (void)printf(_("\nCluster state including:\n"));
    (void)printf(_("  Normal                 cluster is available with data replication\n"));
    (void)printf(_("  Degraded               cluster is available without data replication\n"));
    (void)printf(_("  Unavailable            cluster is unavailable\n"));

    (void)printf(_("\nInstance state including:\n"));
    (void)printf(_("  Primary                database system run as a primary server, send xlog to standby server\n"));
    (void)printf(
        _("  Standby                database system run as a standby server, receive xlog from primary server\n"));
#ifdef ENABLE_MULTIPLE_NODES
    (void)printf(
        _("  Secondary              database system run as a dummy standby server, receive xlog from primary server "
          "when standby server down\n"));
#endif
#ifndef ENABLE_PRIVATEGAUSS
    (void)printf(_("  Cascade Standby        database system run as a cascade standby server, receive xlog from "
                   "standby server\n"));
#endif
#ifdef ENABLE_LIBPQ
    (void)printf(_("  Pending                database system run as a pending server, wait for promoting to primary or "
                   "demoting to standby\n"));
#endif
    (void)printf(_("  Down                   database system not running\n"));
    (void)printf(_("  Unknown                database system not connected\n"));

    (void)printf(_("\nHA state including:\n"));
    (void)printf(_("  Normal                 database system is normal\n"));
    (void)printf(_("  Need repair            database system is not connected with primary/standby server or not "
                   "matched with primary/standby server\n"));
    (void)printf(_("  Wait promoting         database system is waiting to promote during switchover\n"));
    (void)printf(_("  Promoting              database system is promoting\n"));
    (void)printf(_("  Building               database system is building\n"));
    (void)printf(_("  Catchup                database system is catching up xlog\n"));
    (void)printf(_("  Demoting               database system is demoting\n"));
    (void)printf(_("  Starting               database system is starting up\n"));
    (void)printf(_("  Manually stopped       database system is down for being manually stopped\n"));
    (void)printf(_("  Disk damaged           database system is down for disk damaged\n"));
    (void)printf(_("  Port conflicting       database system is down for port conflicting\n"));
    (void)printf(_("  Unknown                database system is down for some internal error\n"));
}

#ifdef ENABLE_LIBPQ
static void SetRunmodeHelp()
{
    (void)printf(_("\nOptions for setrunmode:\n"));
    (void)printf(_("  --xmode                minority or normal.\n"));
    (void)printf(_("  --votenum              in minority mode,available dn vote number.\n"));
}

static void ChangeRoleHelp()
{
    (void)printf(_("\nOptions for changerole:\n"));
    (void)printf(_("  --role                 switch dcf role to passive or to follower.\n"));
}

static void ChangeMemberHelp()
{
    (void)printf(_("\nOptions for changemember:\n"));
    (void)printf(_("  --role                 switch dcf role to passive or to follower.\n"));
    (void)printf(_("  --group                change dcf group id.\n"));
    (void)printf(_("  --priority             change dcf election priority.\n"));
}
#endif

static void ReloadHelp()
{
    (void)printf(_("\nOptions for reload:\n"));
    (void)printf(_("  reload                 reload cluster static config online.\n"));
    (void)printf(_("  --param                reload conf param\n"));
    (void)printf(_("  --agent                reload cm_agent conf.\n"));
    (void)printf(_("  --server               reload cm_server conf.\n"));
}

static void ListHelp()
{
    (void)printf(_("\nOptions for list:\n"));
    (void)printf(_("  --param                list conf param\n"));
    (void)printf(_("  --agent                list the cm_agent parameter.\n"));
    (void)printf(_("  --server               list the cm_server parameter.\n"));
}

static void EncryptHelp()
{
    (void)printf(_("\nOptions for encrypt:\n"));
    (void)printf(_("  -M                     encrypt mode (server,client), default value is server mode.\n"));
    (void)printf(_("  -D                     appoint encrypt file path.\n"));
}

static void SwitchDdbHelp()
{
    (void)printf(_("\nOptions for switch ddb:\n"));
    (void)printf(_("  --ddb_type             switch to which ddb type.\n"));
    (void)printf(_("  --commit               after switch success, need do commit.\n"));
    (void)printf(_("  --rollback             when something wrong, can do rollback.\n"));
}

static void DccCmdHelp()
{
    (void)printf(_("\nOptions for ddb cmd:\n"));
    (void)printf(_("  --help, -h             Shows help information of ddb cmd.\n"));
    (void)printf(_("  --version, -v          Shows version information of dcc.\n"));
    (void)printf(_("  --get key              Queries the value of a specified key.\n"));
    (void)printf(_("  --put key val          Updates or insert the value of a specified key.\n"));
    (void)printf(_("  --delete key           Deletes the specified key.\n"));
    (void)printf(_("  --prefix               Prefix matching --get or --delete.\n"));
    (void)printf(_("  --cluster_info         show cluster info of dcc.\n"));
    (void)printf(_("  --leader_info          show leader nodeid of dcc.\n"));
}

static void ResCmdHelp()
{
    (void)printf(_("\nOptions for res cmd:\n"));
    (void)printf(_("  --add                  add one resource configuration information.\n"));
    (void)printf(_("  --edit                 edit one resource or resource instances configuration information.\n"));
    (void)printf(_("  --del                  delete one resource or resource instances configuration information.\n"));
    (void)printf(_("  --check                check whether the resource configuration information regular.\n"));
    (void)printf(_("  --list                 list one resource or resource instances configuration information.\n"));
    (void)printf(_("  --res_name             specifies the name of the resource to be operated.\n"));
    (void)printf(_("  --res_attr             common resource configuration information.\n"));
    (void)printf(_("  --inst_attr            common instances configuration information.\n"));
    (void)printf(_("  --add_inst             add instances configuration information of one resource.\n"));
    (void)printf(_("  --del_inst             delete instances configuration information of one resource.\n"));
    (void)printf(_("  --edit_inst            edit instances configuration information of one resource.\n"));
    (void)printf(_("  --list_inst            list instances configuration information of one resource.\n"));
}

void DoHelp(const char *projectName)
{
    (void)printf(_("%s is a utility to start, stop, query or control a mppdb cluster.\n\n"), projectName);
    UsageHelp(projectName);
    CommonHelp();
    SwitchoverHelp();
    BuildHelp();
    CheckHelp();
    StartAndStopHelp();
    QueryHelp();

#ifdef ENABLE_MULTIPLE_NODES
    RestartHelp();
#endif

    SetAndGetHelp();
    OptionsForView();

#if defined(ENABLE_MULTIPLE_NODES) || defined(ENABLE_PRIVATEGAUSS)
    OptionsForHotpatch();
#endif
#ifdef ENABLE_LIBPQ
    SetRunmodeHelp();
    ChangeRoleHelp();
    ChangeMemberHelp();
#endif
    ReloadHelp();
    ListHelp();
    EncryptHelp();
    SwitchDdbHelp();
    ShutdownModeHelp();
    StatusHelp();
    DccCmdHelp();
    ResCmdHelp();
}
