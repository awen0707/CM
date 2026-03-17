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
# Description  : InstallImpl.py
#############################################################################

from curses.ascii import isdigit, islower, isupper
import os
import re
import subprocess
import getpass
from ErrorCode import ErrorCode
from Common import executeCmdOnHost

class InstallImpl:
    def __init__(self, install):
        self.cmpkg = install.cmpkg
        self.context = install
        self.envFile = install.envFile
        self.xmlFile = install.xmlFile
        self.cmDirs = install.cmDirs
        self.hostnames = install.hostnames
        self.gaussHome = install.gaussHome
        self.gaussLog = install.gaussLog
        self.toolPath = install.toolPath
        self.tmpPath = install.tmpPath
        self.localhostName = install.localhostName
        self.logger = install.logger
        self.clusterStopped = install.clusterStopped
        self.primaryTermAbnormal = install.primaryTermAbnormal

    def executeCmdOnHost(self, host, cmd, isLocal = False):
        if host == self.localhostName:
            isLocal = True
        return executeCmdOnHost(host, cmd, isLocal)

    def prepareCMPath(self):
        """
        create path: cmdir、cmdir/cm_server、cmdir/cm_agent
        """
        self.logger.log("Preparing CM path.")
        for (cmdir, host) in zip(self.cmDirs, self.hostnames):
            cmd = "mkdir -p {cmdir}/cm_server {cmdir}/cm_agent".format(cmdir=cmdir)
            status, output = self.executeCmdOnHost(host, cmd)
            if status != 0:
                self.logger.debug("Command: " + cmd)
                errorDetail = "\nStatus: %s\nOutput: %s" % (status, output)
                self.logger.logExit("Failed to create CM path." + errorDetail)

    def decompressCMPkg(self):
        self.logger.log("Decompressing CM pacakage.")
        if self.cmpkg == "":
            return
        # decompress cm pkg on localhost
        decompressCmd = "tar -zxf %s -C %s" % (self.cmpkg, self.gaussHome)
        status, output = subprocess.getstatusoutput(decompressCmd)
        if status != 0:
            self.logger.debug("Command: " + decompressCmd)
            errorDetail = "\nStatus: %s\nOutput: %s" % (status, output)
            self.logger.logExit("Failed to decompress cm pacakage to on localhost." + errorDetail)

        # If the version of CM pacakage is inconsistent with that of gaussdb,
        # then exit. So no need to send CM pacakage to other nodes.
        self.checkCMPkgVersion()

        # decompress cmpkg on other hosts
        cmpkgName = os.path.basename(self.cmpkg)
        for host in self.hostnames:
            if host == self.localhostName:
                continue
            # copy cm pacakage to other hosts
            if ":" in host:
                host = "[" + host + "]"
            scpCmd = "scp %s %s:%s" % (self.cmpkg, host, self.toolPath)
            status, output = subprocess.getstatusoutput(scpCmd)
            if status != 0:
                self.logger.debug("Command: " + scpCmd)
                errorDetail = "\nStatus: %s\nOutput: %s" % (status, output)
                self.logger.logExit(("Failed to send cm pacakage to %s." % host) + errorDetail)
            pkgPath = os.path.join(self.toolPath, cmpkgName)
            decompressCmd = "tar -zxf %s -C %s" % (pkgPath, self.gaussHome)
            status, output = self.executeCmdOnHost(host, decompressCmd)
            if status != 0:
                self.logger.debug("Command: " + decompressCmd)
                errorDetail = "\nStatus: %s\nOutput: %s" % (status, output)
                self.logger.logExit(("Failed to decompress cm pacakage to on host %s." % host) + errorDetail)

    def checkCMPkgVersion(self):
        getCMVersionCmd = "source %s; cm_ctl -V" % self.envFile
        status, output = subprocess.getstatusoutput(getCMVersionCmd)
        if status != 0:
            self.logger.logExit("Failed to get CM pacakage version.")
        cmVersionList = re.findall(r'.*CM (\d.*\d) build', output)
        if len(cmVersionList) == 0:
            self.logger.logExit("Failed to get CM pacakage version.")
        cmVersion = cmVersionList[0]

        getGaussdbVersionCmd = "source %s; gaussdb -V" % self.envFile
        status, output = subprocess.getstatusoutput(getGaussdbVersionCmd)
        if status != 0:
            self.logger.logExit("Failed to get gaussdb version.")
        gaussdbVersionList = re.findall(r'openGauss (\d.*\d) build', output)
        if len(gaussdbVersionList) == 0:
            self.logger.logExit("Failed to get gaussdb version.")
        gaussdbVersion = gaussdbVersionList[0]

        if gaussdbVersion != cmVersion:
            self.logger.logExit("The version of CM pacakage(%s) is inconsistent "
                "with that of gaussdb(%s)." % (cmVersion, gaussdbVersion))

    def createManualStartFile(self):
        self.logger.log("Creating cluster_manual_start file.")
        cmd = """
            if [ ! -f {gaussHome}/bin/cluster_manual_start ]; then
                touch {gaussHome}/bin/cluster_manual_start
            fi
            """.format(gaussHome=self.gaussHome)
        for host in self.hostnames:
            status, output = self.executeCmdOnHost(host, cmd)
            if status != 0:
                self.logger.debug("Command: " + cmd)
                errorDetail = "\nStatus: %s\nOutput: %s" % (status, output)
                self.logger.logExit("Failed to create cluster_manual_start file." + errorDetail)

    def initCMServer(self):
        self.logger.log("Initializing cm_server.")
        for (cmdir, host) in zip(self.cmDirs, self.hostnames):
            cmd = """
                cp {gaussHome}/share/config/cm_server.conf.sample {cmdir}/cm_server/cm_server.conf
                sed 's#log_dir = .*#log_dir = {gaussLog}/cm/cm_server#' {cmdir}/cm_server/cm_server.conf -i
                """.format(gaussHome=self.gaussHome, gaussLog=self.gaussLog, cmdir=cmdir)
            status, output = self.executeCmdOnHost(host, cmd)
            if status != 0:
                self.logger.debug("Command: " + cmd)
                errorDetail = "\nStatus: %s\nOutput: %s" % (status, output)
                self.logger.logExit("Failed to initialize cm_server." + errorDetail)

    def initCMAgent(self):
        self.logger.log("Initializing cm_agent.")
        for (cmdir, host) in zip(self.cmDirs, self.hostnames):
            cmd = """
                cp {gaussHome}/share/config/cm_agent.conf.sample {cmdir}/cm_agent/cm_agent.conf && 
                sed 's#log_dir = .*#log_dir = {gaussLog}/cm/cm_agent#' {cmdir}/cm_agent/cm_agent.conf -i && 
                sed 's#unix_socket_directory = .*#unix_socket_directory = {gaussHome}#' {cmdir}/cm_agent/cm_agent.conf -i
                """.format(gaussHome=self.gaussHome, gaussLog=self.gaussLog, cmdir=cmdir)
            status, output = self.executeCmdOnHost(host, cmd)
            if status != 0:
                self.logger.debug("Command: " + cmd)
                errorDetail = "\nStatus: %s\nOutput: %s" % (status, output)
                self.logger.logExit("Failed to initialize cm_agent." + errorDetail)

    def setMonitorCrontab(self):
        """
        set om_monitor crontab
        """
        self.logger.log("Setting om_monitor crontab.")
        # save old crontab content to cronContentTmpFile
        cronContentTmpFile = os.path.join(self.tmpPath, "cronContentTmpFile_" + str(os.getpid()))
        listCronCmd = "crontab -l > %s" % cronContentTmpFile
        status, output = self.executeCmdOnHost(self.localhostName, listCronCmd)
        if status != 0:
            self.logger.debug("Command: " + listCronCmd)
            errorDetail = "\nStatus: %s\nOutput: %s" % (status, output)
            self.logger.logExit(ErrorCode.GAUSS_508["GAUSS_50804"] + errorDetail)
        # if old crontab content contains om_monitor, clear it
        clearMonitorCmd = "sed '/.*om_monitor.*/d' %s -i" % cronContentTmpFile
        status, output = subprocess.getstatusoutput(clearMonitorCmd)
        if status != 0:
            os.remove(cronContentTmpFile)
            self.logger.debug("Command: " + clearMonitorCmd)
            errorDetail = "\nStatus: %s\nOutput: %s" % (status, output)
            self.logger.logExit("Failed to clear old om_monitor crontab." + errorDetail)

        # generate om_monitor crontab command and append it to cronContentTmpFile
        startMonitorCmd = "source /etc/profile;(if [ -f ~/.profile ];" \
                      "then source ~/.profile;fi);source ~/.bashrc;"
        if self.envFile != "~/.bashrc":
            startMonitorCmd += "source %s; " % (self.envFile)
        monitorLogPath = os.path.join(self.gaussLog, "cm")
        if not os.path.exists(monitorLogPath):
            os.makedirs(monitorLogPath)
        startMonitorCmd += "nohup om_monitor -L %s/om_monitor >>/dev/null 2>&1 &" % monitorLogPath
        monitorCron = "*/1 * * * * " + startMonitorCmd + os.linesep
        with open(cronContentTmpFile, 'a+', encoding='utf-8') as fp:
            fp.writelines(monitorCron)
            fp.flush()

        # set crontab on other hosts
        setCronCmd = "crontab %s" % cronContentTmpFile
        cleanTmpFileCmd = "rm %s -f" % cronContentTmpFile
        username = getpass.getuser()
        killMonitorCmd = "pkill om_monitor -u %s; " % username
        for host in self.hostnames:
            if host == self.localhostName:
                continue
            # copy cronContentTmpFile to other host
            if ":" in host:
                host = "[" + host + "]"
            scpCmd = "scp %s %s:%s" % (cronContentTmpFile, host, self.tmpPath)
            status, output = subprocess.getstatusoutput(scpCmd)
            if status != 0:
                self.logger.debug("Command: " + scpCmd)
                errorDetail = "\nStatus: %s\nOutput: %s" % (status, output)
                self.logger.logExit(("Failed to copy cronContentTmpFile to %s." % host) + errorDetail)
            # set om_monitor crontab
            status, output = self.executeCmdOnHost(host, setCronCmd)
            # cleanup cronContentTmpFile
            self.executeCmdOnHost(host, cleanTmpFileCmd)
            if status != 0:
                self.logger.debug("Command: " + setCronCmd)
                errorDetail = "\nStatus: %s\nOutput: %s" % (status, output)
                self.logger.logExit(ErrorCode.GAUSS_508["GAUSS_50801"] + errorDetail)

            # start om_monitor
            # Firstly, kill residual om_monitor, otherwise cm_agent won't be started if there are residual om_monitor process.
            status, output = self.executeCmdOnHost(host, killMonitorCmd + startMonitorCmd)
            if status != 0:
                self.logger.debug("Command: " + startMonitorCmd)
                errorDetail = "\nStatus: %s\nOutput: %s" % (status, output)
                self.logger.logExit((ErrorCode.GAUSS_516["GAUSS_51607"] % "om_monitor") + errorDetail)

        # set crontab on localhost
        status, output = subprocess.getstatusoutput(setCronCmd)
        os.remove(cronContentTmpFile)
        if status != 0:
            self.logger.debug("Command: " + setCronCmd)
            errorDetail = "\nStatus: %s\nOutput: %s" % (status, output)
            self.logger.logExit(ErrorCode.GAUSS_508["GAUSS_50801"] + errorDetail)

        status, output = subprocess.getstatusoutput(killMonitorCmd + startMonitorCmd)
        if status != 0:
            self.logger.debug("Command: " + startMonitorCmd)
            errorDetail = "\nStatus: %s\nOutput: %s" % (status, output)
            self.logger.logExit((ErrorCode.GAUSS_516["GAUSS_51607"] % "om_monitor") + errorDetail)

    def startCluster(self):
        self.logger.log("Starting cluster.")
        startCmd = "source %s; cm_ctl start" % self.envFile
        status, output = subprocess.getstatusoutput(startCmd)
        if status != 0:
            self.logger.debug("Command: " + startCmd)
            errorDetail = "\nStatus: %s\nOutput: %s" % (status, output)
            self.logger.logExit("Failed to start cluster." + errorDetail)

        status, output = InstallImpl.refreshDynamicFile(self.envFile)
        if status != 0:
            self.logger.error("Failed to refresh dynamic file." + output)

        queryCmd = "source %s; cm_ctl query -Cv" % self.envFile
        status, output = subprocess.getstatusoutput(queryCmd)
        if status != 0:
            self.logger.debug("Command: " + queryCmd)
            errorDetail = "\nStatus: %s\nOutput: %s" % (status, output)
            self.logger.logExit("Failed to query cluster status." + errorDetail)
        self.logger.log(output)
        self.logger.log("Install CM tool success.")
        if self.primaryTermAbnormal:
            self.logger.warn("Term of primary is invalid or not maximal.\n"
                "Hint: To avoid CM arbitration anomalies in this situation, "
                "please restart the database.\n"
                "Command : cm_ctl stop && cm_ctl start")

    @staticmethod
    def refreshStaticFile(envFile, xmlFile):
        """
        refresh static and dynamic file using xml file with cm
        """
        # refresh static file
        cmd = """
            source {envFile};
            gs_om -t generateconf -X {xmlFile} --distribute
            """.format(envFile=envFile, xmlFile=xmlFile)
        status, output = subprocess.getstatusoutput(cmd)
        errorDetail = ""
        if status != 0:
            errorDetail = "\nCommand: %s\nStatus: %s\nOutput: %s" % (cmd, status, output)
        return status, errorDetail

    @staticmethod
    def refreshDynamicFile(envFile):
        # refresh dynamic file
        refreshDynamicFileCmd = "source %s; gs_om -t refreshconf" % envFile
        status, output = subprocess.getstatusoutput(refreshDynamicFileCmd)
        errorDetail = ""
        if status != 0:
            errorDetail = "\nCommand: %s\nStatus: %s\nOutput: %s" % (refreshDynamicFileCmd, status, output)
        return status, errorDetail

    def _refreshStaticFile(self):
        self.logger.log("Refreshing static and dynamic file using xml file with cm.")
        status, output  = InstallImpl.refreshStaticFile(self.envFile, self.xmlFile)
        if status != 0:
            self.logger.logExit("Failed to refresh static file." + output)

    @staticmethod
    def checkPassword(passwordCA):
        minPasswordLen = 8
        maxPasswordLen = 15
        kinds = [0, 0, 0, 0]
        specLetters = "~!@#$%^&*()-_=+\\|[{}];:,<.>/?"
        if len(passwordCA) < minPasswordLen:
            print("Invalid password, it must contain at least eight characters.")
            return False
        if len(passwordCA) > maxPasswordLen:
            print("Invalid password, it must contain at most fifteen characters.")
            return False
        for c in passwordCA:
            if isdigit(c):
                kinds[0] += 1
            elif isupper(c):
                kinds[1] += 1
            elif islower(c):
                kinds[2] += 1
            elif c in specLetters:
                kinds[3] += 1
            else:
                print("The password contains illegal character: %s." % c)
                return False
        kindsNum = 0
        for k in kinds:
            if k > 0:
                kindsNum += 1
        if kindsNum < 3:
            print("The password must contain at least three kinds of characters.")
            return False
        return True

    def _getPassword(self):
        passwordCA = ""
        passwordCA2 = ""
        tryCount = 0
        while tryCount < 3:
            passwordCA = getpass.getpass("Please input the password for ca cert:")
            passwordCA2 = getpass.getpass("Please input the password for ca cert again:")
            if passwordCA != passwordCA2:
                tryCount += 1
                self.logger.printMessage("The password enterd twice do not match.")
                continue
            if not InstallImpl.checkPassword(passwordCA):
                tryCount += 1
                continue
            break
        if tryCount == 3:
            self.logger.logExit("Maximum number of attempts has been reached.")
        return passwordCA

    def _createCMSslConf(self, certPath):
        """
        Generate config file.
        """
        self.logger.debug("OPENSSL: Create config file.")
        v3CaL = [
            "[ v3_ca ]",
            "subjectKeyIdentifier=hash",
            "authorityKeyIdentifier=keyid:always,issuer:always",
            "basicConstraints = CA:true",
            "keyUsage = keyCertSign,cRLSign",
        ]
        v3Ca = os.linesep.join(v3CaL)

        # Create config file.
        with open(os.path.join(certPath, "openssl.cnf"), "w") as fp:
            # Write config item of Signature
            fp.write(v3Ca)
        self.logger.debug("OPENSSL: Successfully create config file.")

    def _cleanUselessFile(self):
        """
        Clean useless files
        :return: NA
        """
        certPath = os.path.join(self.gaussHome, "share/sslcert/cm")
        keyFiles = ["cacert.pem", "server.crt", "server.key", "client.crt", "client.key",
            "server.key.cipher", "server.key.rand", "client.key.cipher", "client.key.rand"]
        for fileName in os.listdir(certPath):
            filePath = os.path.join(certPath, fileName)
            if fileName not in keyFiles:
                os.remove(filePath)

    def _createCMCALocal(self):
        self.logger.debug("Creating Cm ca files locally.")
        certPath = os.path.join(self.gaussHome, "share/sslcert/cm")
        mkdirCmd = "rm %s -rf; mkdir %s" % (certPath, certPath)
        status, output = subprocess.getstatusoutput(mkdirCmd)
        if status != 0:
            self.logger.debug("Command: %s\nStatus: %sOutput: %s" % (mkdirCmd, status, output))
            self.logger.logExit("Failed to create cert path.")
        self._createCMSslConf(certPath)
        curPath = os.path.split(os.path.realpath(__file__))[0]
        createCMCACert = os.path.realpath(os.path.join(curPath, "CreateCMCACert.sh"))
        passwd = self._getPassword()
        cmd = "source %s; echo \"%s\" | sh %s" % (self.envFile, passwd, createCMCACert)
        # once used, set password to null and release it
        passwd = ""
        del passwd
        status, output = subprocess.getstatusoutput(cmd)
        cmd = ""
        del cmd
        if status != 0:
            self.logger.logExit("Failed to create cm ca cert file.\n" + output)
        self._cleanUselessFile()

    def _distributeCA(self):
        self.logger.debug("Distributing CM ca files to other hosts.")
        certPath = os.path.join(self.gaussHome, "share/sslcert/cm")
        createCertPathCmd = "rm {certPath} -rf; mkdir {certPath}; chmod 700 {certPath}".format(
            certPath=certPath)
        for host in self.hostnames:
            if host == self.localhostName:
                continue
            status, output = self.executeCmdOnHost(host, createCertPathCmd)
            if status != 0:
                errorDetail = "\nCommand: %s\nStatus: %s\nOutput: %s" % (createCertPathCmd, status, output)
                self.logger.debug(errorDetail)
                self.logger.logExit("Failed to create path of CA for CM on host %s." % host)
            # Determine if the host is an IPv6 address and format accordingly
            if ":" in host:
                formatted_host = "[{}]".format(host)
            else:
                formatted_host = host
        
            # Create the scp command with the formatted host
            scpCmd = "scp {certPath}/* {host}:{certPath}".format(certPath=certPath, host=formatted_host)
            status, output = subprocess.getstatusoutput(scpCmd)
            if status != 0:
                errorDetail = "\nCommand: %s\nStatus: %s\nOutput: %s" % (scpCmd, status, output)
                self.logger.debug(errorDetail)
                self.logger.logExit("Failed to create CA for CM.")

    def createCMCA(self):
        self.logger.log("Creating CM ca files.")
        self._createCMCALocal()
        self._distributeCA()

    def run(self):
        self.logger.log("Start to install cm tool.")
        self.prepareCMPath()
        self.decompressCMPkg()
        self.createManualStartFile()
        self.initCMServer()
        self.initCMAgent()
        self.createCMCA()
        self._refreshStaticFile()
        self.setMonitorCrontab()
        self.startCluster()
