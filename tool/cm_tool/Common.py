# -*- coding:utf-8 -*-
#############################################################################
# Copyright (c) 2022 Huawei Technologies Co.,Ltd.
#
# openGauss is licensed under Mulan PSL v2.
# You can use this software according to the terms
# and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#
#          http://license.coscl.org.cn/MulanPSL2
#
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS,
# WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.
# ----------------------------------------------------------------------------
# Description  : Common.py includes some public function
#############################################################################

import os
import subprocess
from CMLog import CMLog
from ErrorCode import ErrorCode

def getEnvParam(envFile, param):
    cmd = "source {envFile}; echo ${param}".format(envFile=envFile, param=param)
    status, output = subprocess.getstatusoutput(cmd)
    if status != 0:
        errorDetail = "\nCommand: %s\nStatus: %s\nOutput: %s\n" % (
            cmd, status, output)
        CMLog.exitWithError(ErrorCode.GAUSS_518["GAUSS_51802"] % param)
    return output

def getLocalhostName():
    import socket
    return socket.gethostname()

def executeCmdOnHost(host, cmd, isLocal = False):
    if not isLocal:
        cmd = 'ssh -q -o ConnectTimeout=5 %s \"%s\"' % (host, cmd)
    status, output = subprocess.getstatusoutput(cmd)
    return status, output

def checkXMLFile(xmlFile):
    """
    function: check XML file
            1.check whether XML file exists
            2.check whether XML file is file
            3.permission
    input : NA
    output: NA
    """
    if xmlFile.startswith('~/'):
        homePath = os.path.expanduser('~')
        xmlFile = homePath + xmlFile[1:]
    if not os.path.exists(xmlFile):
        CMLog.exitWithError(ErrorCode.GAUSS_502["GAUSS_50201"] % "xmlFile")
    if not os.path.isfile(xmlFile):
        CMLog.exitWithError(ErrorCode.GAUSS_502["GAUSS_50210"] % "xmlFile")
    if not os.access(xmlFile, os.R_OK):
        CMLog.exitWithError(ErrorCode.GAUSS_501["GAUSS_50100"] % (xmlFile, "current user"))

def checkHostsTrust(hosts):
    """
    check trust between current host and the given hosts
    """
    hostsWithoutTrust = []
    for host in hosts:
        checkTrustCmd = "ssh -o ConnectTimeout=3 -o ConnectionAttempts=5 -o PasswordAuthentication=no " \
            "-o StrictHostKeyChecking=no %s 'pwd > /dev/null'" % host
        status, output = subprocess.getstatusoutput(checkTrustCmd)
        if status != 0:
            hostsWithoutTrust.append(host)
    if hostsWithoutTrust != []:
        CMLog.exitWithError(ErrorCode.GAUSS_511["GAUSS_51100"] % ','.join(hostsWithoutTrust))
