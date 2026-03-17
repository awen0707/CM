# -*- coding:utf-8 -*-
#############################################################################
# Portions Copyright (c) 2022 Huawei Technologies Co.,Ltd.
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
# Description  : CMLog.py is utility to handle the log
#############################################################################
import os
import sys
import datetime
import subprocess
import _thread as thread
import re
import logging.handlers as _handlers
import time

sys.path.append(sys.path[0] + "/../../")

from ErrorCode import ErrorCode

# import typing for comment.
try:
    from typing import Dict
    from typing import List
except ImportError:
    Dict = dict
    List = list

# max log file size
# 16M
MAXLOGFILESIZE = 16 * 1024 * 1024

LOG_DEBUG = 1
LOG_INFO = 2
LOG_WARNING = 2.1
LOG_ERROR = 3
LOG_FATAL = 4


class CMLog:
    """
    Class to handle log file
    """

    def __init__(self, logPath, module, prefix, suffix = ".log", expectLevel=LOG_DEBUG, traceId=None):
        """
        function: Constructor
        input : NA
        output: NA
        """
        self.logFile = ""
        self.expectLevel = expectLevel
        self.moduleName = module
        self.fp = None
        self.size = 0
        self.suffix = suffix
        self.prefix = prefix
        self.logPath = logPath
        self.pid = os.getpid()
        self.step = 0
        self.lock = thread.allocate_lock()
        self.tmpFile = None
        self.ignoreErr = False
        self.traceId = traceId

        try:
            if not os.path.isdir(logPath):
                print(ErrorCode.GAUSS_502["GAUSS_50211"] % logPath)
                sys.exit(1)
            # check log path
            if not os.path.exists(logPath):
                try:
                    os.makedirs(logPath, 0o700)
                except Exception as e:
                    raise Exception(ErrorCode.GAUSS_502["GAUSS_50208"] %
                                    logPath + " Error:\n%s" % str(e))
            # create new log file
            self.__openLogFile()
        except Exception as ex:
            print(str(ex))
            sys.exit(1)

    def __checkLink(self):
        """
        function: check log file is link
        input : NA
        output: list of
        """
        if os.path.islink(self.logFile):
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50206"] % self.logFile)

    def __checkLogFileExist(self):
        """
        check whether log file exists, if exist, get log file name
        log file name format: 
            prefix-YYYY-mm-DD_HHMMSSsuffix = cm_install-YYYY-mm-DD_HHMMSS.log
        """
        logFileList = "%s/logFileList_%s.dat" % (self.logPath, self.pid)
        cmd = "ls %s | grep '^%s-.*%s$' > %s" % (
            self.logPath, self.prefix, self.suffix, logFileList)
        (status, output) = subprocess.getstatusoutput(cmd)
        if status != 0:
            if os.path.exists(logFileList):
                os.remove(logFileList)
            return False
        with open(logFileList, "r") as fp:
            filenameList = []
            while True:
                # get real file name
                filename = (fp.readline()).strip()
                if not filename:
                    break
                existedResList = filename.split(".")
                if len(existedResList) > 2:
                    continue
                (existedPrefix, existedSuffix) = \
                    os.path.splitext(filename)
                if existedSuffix != self.suffix:
                    continue
                if len(filename) != len(self.prefix) + \
                    len(self.suffix) + 18:
                    continue
                timeStamp = existedPrefix[-17:]
                # check log file name
                if self.__isValidDate(timeStamp):
                    filenameList.append(filename)
        # cleanup logFileList
        if os.path.exists(logFileList):
            os.remove(logFileList)

        if len(filenameList) == 0:
            return False
        # get logFile
        fileName = max(filenameList)
        self.logFile = os.path.join(self.logPath, fileName)
        self.__checkLink()
        return True

    def __openLogFile(self):
        """
        function: open log file
        input : NA
        output: NA
        """
        try:
            if self.__checkLogFileExist():
                self.fp = open(self.logFile, "a")
                return
            # get current time
            currentTime = time.strftime("%Y-%m-%d_%H%M%S")
            # init log file
            self.logFile = os.path.join(self.logPath, self.prefix + "-" + currentTime + self.suffix)
            # Re-create the log file to add a retry 3 times mechanism,
            # in order to call concurrently between multiple processes
            retryTimes = 3
            count = 0
            while (True):
                (status, output) = self.__createLogFile()
                if status == 0:
                    break
                count = count + 1
                time.sleep(1)
                if (count > retryTimes):
                    raise Exception(output)
            # open log file
            self.__checkLink()
            self.fp = open(self.logFile, "a")
        except Exception as e:
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50206"]
                            % self.logFile + " Error:\n%s" % str(e))

    def __createLogFile(self):
        """
        function: create log file
        input : NA
        output: (status, output)
        """
        try:
            if (not os.path.exists(self.logFile)):
                os.mknod(self.logFile)
            return (0, "")
        except Exception as e:
            return (1, str(e))

    def __isValidDate(self, datastr):
        """
        function: Judge if date valid
        input : datastr
        output: bool
        """
        try:
            time.strptime(datastr, "%Y-%m-%d_%H%M%S")
            return True
        except Exception as ex:
            return False

    def closeLog(self):
        """
        function: Function to close log file
        input : NA
        output: NA
        """
        try:
            if self.fp:
                self.fp.flush()
                self.fp.close()
                self.fp = None
        except Exception as ex:
            if self.fp:
                self.fp.close()
            raise Exception(str(ex))

    # print the flow message to console window and log file
    # AddInfo: constant represent step constant, addStep represent step
    # plus, None represent no step
    def log(self, msg, stepFlag=""):
        """
        function:print the flow message to console window and log file
        input:   msg,stepFlag
        control: when stepFlag="", the OM background log does not display
        step information.
                 when stepFlag="addStep", the OM background log step will
                 add 1.
                 when stepFlag="constant", the OM background log step
                 defaults to the current step.
        output:  NA
        """
        if (LOG_INFO >= self.expectLevel):
            print(msg)
            self.__writeLog("LOG", msg, stepFlag)

    # print the flow message to log file only
    def debug(self, msg, stepFlag=""):
        """
        function:print the flow message to log file only
        input:   msg,stepFlag
        control: when stepFlag="", the OM background log does not display
        step information.
                 when stepFlag="addStep", the OM background log step will
                 add 1.
                 when stepFlag="constant", the OM background log step
                 defaults to the current step.
        output:  NA
        """
        if (LOG_DEBUG >= self.expectLevel):
            self.__writeLog("DEBUG", msg, stepFlag)

    def warn(self, msg, stepFlag=""):
        """
        function:print the flow message to log file only
        input:   msg,stepFlag
        control: when stepFlag="", the OM background log does not display
        step information.
                 when stepFlag="addStep", the OM background log step will
                 add 1.
                 when stepFlag="constant", the OM background log step
                 defaults to the current step.
        output:  NA
        """
        if (LOG_WARNING >= self.expectLevel):
            print(msg)
            self.__writeLog("WARNING", msg, stepFlag)

    # print the error message to console window and log file
    def error(self, msg):
        """
        function: print the error message to console window and log file
        input : msg
        output: NA
        """
        if (LOG_ERROR >= self.expectLevel):
            print(msg)
            self.__writeLog("ERROR", msg)

    # print the error message to console window and log file,then exit
    def logExit(self, msg):
        """
        function: print the error message to console window and log file,
        then exit
        input : msg
        output: NA
        """
        if (LOG_FATAL >= self.expectLevel):
            print(msg)
            try:
                self.__writeLog("ERROR", msg)
            except Exception as ex:
                print(str(ex))
        self.closeLog()
        sys.exit(1)

    def Step(self, stepFlag):
        """
        function: return Step number info
        input: add
        output: step number
        """
        if (stepFlag == "constant"):
            return self.step
        else:
            self.step = self.step + 1
            return self.step

    def __getLogFileLine(self):
        f = sys._getframe().f_back.f_back.f_back
        return "%s(%s:%s)" % (os.path.basename(f.f_code.co_filename), f.f_code.co_name,
                              str(f.f_lineno))

    def __writeLog(self, level, msg, stepFlag=""):
        """
        function: Write log to file
        input: level, msg, stepFlag
        output: NA
        """
        if self.fp is None:
            return

        try:
            self.lock.acquire()
            # if the log file does not exits, create it
            if (not os.path.exists(self.logFile)):
                self.__openLogFile()
            else:
                logPer = oct(os.stat(self.logFile).st_mode)[-3:]
                self.__checkLink()
                if not logPer == "600":
                    os.chmod(self.logFile, 0o600)
            # check if need switch to an new log file
            self.size = os.path.getsize(self.logFile)
            if self.size >= MAXLOGFILESIZE and os.getuid() != 0:
                self.closeLog()
                self.__openLogFile()

            replaceReg = re.compile(r'-W[ ]*[^ ]*[ ]*')
            msg = replaceReg.sub('-W *** ', str(msg))

            if msg.find("gs_redis") >= 0:
                replaceReg = re.compile(r'-A[ ]*[^ ]*[ ]*')
                msg = replaceReg.sub('-A *** ', str(msg))

            strTime = datetime.datetime.now()
            fileLine = self.__getLogFileLine()
            if stepFlag == "":
                if self.traceId:
                    print("[%s][%s][%d][%s][%s]:%s"
                          % (self.traceId, strTime, self.pid, self.moduleName,
                             level, msg), file=self.fp)
                else:
                    print("[%s][%d][%s][%s]:%s" % (
                        strTime, self.pid, self.moduleName, level, msg),
                        file=self.fp)
            else:
                stepnum = self.Step(stepFlag)
                print("[%s][%d][%s][%s][%s][Step%d]:%s" % (
                    strTime, self.pid, fileLine, self.moduleName, level, stepnum, msg),
                      file=self.fp)
            self.fp.flush()
            self.lock.release()
        except Exception as ex:
            self.lock.release()
            if self.ignoreErr:
                return
            raise Exception(ErrorCode.GAUSS_502["GAUSS_50205"]
                            % (("log file %s") % self.logFile) +
                            " Error:\n%s" % str(ex))

    @staticmethod
    def exitWithError(msg, status=1):
        """
        function: Exit with error message
        input: msg, status=1
        output: NA
        """
        sys.stderr.write("%s\n" % msg)
        sys.exit(status)

    @staticmethod
    def printMessage(msg):
        """
        function: Print the String message
        input: msg
        output: NA
        """
        sys.stdout.write("%s\n" % msg)


