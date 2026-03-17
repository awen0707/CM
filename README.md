- [什么是CM](#什么是CM)
- [卸载CM](#卸载CM)
- [编译](#编译)
    - [概述](#概述)
    - [操作系统和软件依赖要求](#操作系统和软件依赖要求)
    - [下载CM](#下载CM)
    - [编译第三方软件](#编译第三方软件)
    - [使用build.sh编译](#使用build编译)
    - [使用命令编译](#使用命令编译)
    - [编译安装包](#编译安装包)
    - [附:DCC动态库获取](#附:DCC动态库获取)
- [安装](#安装)
    - [创建配置文件](#创建配置文件)
    - [初始化安装环境](#初始化安装环境)
    - [执行安装](#执行安装)
- [快速入门](#快速入门)
- [文档](#文档)
- [社区](#社区)
    - [治理](#治理)
    - [交流](#交流)
- [贡献](#贡献)
- [发行说明](#发行说明)
- [许可证](#许可证)

## 什么是CM

CM（Cluster Manager）是一款集群资源管理软件。支持自定义资源监控，提供了数据库主备的状态监控、网络通信故障监控、文件系统故障监控、故障自动主备切换等能力。提供了丰富的集群管理能力，如集群、节点、实例级的启停，集群状态查询、主备切换、日志管理等。


## 编译

### 概述

编译CM至少需要CM和binarylibs两个仓
如果全源码编译最新的CM，则需要额外的DCC,DCF.CBB仓

- CM：CM的主要代码。可以从开源社区获取。

- binarylibs：CM依赖的第三方开源软件，你可以直接编译openGauss-third_party代码获取，也可以从开源社区下载已经编译好的并上传的一个副本。

- DCC：CM依赖的统一配置管理组件，提供配置存储，选主等能力，有关DCC 更详细的介绍可以翻阅DCC仓指导文档。

- DCF：分布式一致性框架，主要提供日志复制能力，有关DCF更详细的介绍可以翻阅DCF仓指导文档

- CBB：公共仓库，用来存放不同组件的公共函数，有关CBB更详细的介绍可以翻阅CBB仓指导文档


对于三方库、GCC的编译以及常见问题，参照博客[openGauss数据库编译指导](https://opengauss.org/zh/blogs/blogs.html?post/xingchen/opengauss_compile/)

对于DCC 相关的编译依赖，可以查看[附:DCC动态库获取](#附:DCC动态库获取)章节。

在编译CM之前，请检查操作系统和软件依赖要求。

CM可以通过一键式shell工具build.sh进行编译，也可以通过命令进行编译。安装包由build.sh生成。

### 操作系统和软件依赖要求

CM支持以下操作系统：

- CentOS 7.6（x86架构）

- openEuler-20.03-LTS（aarch64架构）

适配其他系统，参照博客[openGauss数据库编译指导](https://opengauss.org/zh/blogs/blogs.html?post/xingchen/opengauss_compile/)

以下表格列举了编译CM的系统软件要求。

建议使用从列出的操作系统安装盘或安装源中获取的以下依赖软件的默认安装包进行安装。如果不存在以下软件，请参考推荐的软件版本。

系统软件依赖要求如下：

| 软件               | 推荐版本    |
| ----------------- | ----------------|
| glibc-devel    | 2.17-111      |
| lsb_release   | 4.1              |
| libaio-devel   | 0.3.109-13  |

### 下载CM及依赖组件

可以从开源社区下载CM、DCC、openGauss-third_party。

https://gitee.com/opengauss/CM

可以通过以下网站获取编译好的binarylibs。下载后请解压缩并重命名为**binarylibs**。

https://opengauss.obs.cn-south-1.myhuaweicloud.com/5.1.0/binarylibs/gcc10.3/openGauss-third_party_binarylibs_openEuler_arm.tar.gz

全量源码编译可下载DCC及其依赖的CBB和DCF仓，不下载编译时默认去binarylibs仓查找dcc动态库

现在我们已经拥有完整的CM代码，把它存储在以下目录中（以sda为例）。

- /sda/CM
- /sda/binarylibs
- /sda/openGauss-third_party
- /sda/DCC
- /sda/CBB
- /sda/DCF

### 编译第三方软件

在编译CM之前，需要先编译CM依赖的开源及第三方软件。这些开源及第三方软件存储在openGauss-third_party代码仓库中，通常只需要构建一次。如果开源软件有更新，需要重新构建软件。

用户也可以直接从**binarylibs**库中获取开源软件编译和构建的输出文件。

如果你想自己编译第三方软件，请到openGauss-third_party仓库查看详情。 

执行完上述脚本后，最终编译和构建的结果保存在与**openGauss-third_party**同级的**binarylibs**目录下。在编译**CM**时会用到这些文件。

### 代码编译

##### 使用build.sh编译代码

openGauss-CM中的build.sh是编译过程中的重要脚本工具。该工具集成了软件安装编译和产品安装包编译功能，可快速进行代码编译和打包。。

参数说明请见以下表格。

| 选项  | 缺省值                       | 参数                                   | 说明                                              |
| :---- | :--------------------------- | :------------------------------------- | :------------------------------------------------ |
| -h    | 请勿使用此选项。             | -                                      | 帮助菜单。                                        |
| -m    | release                      | [debug &#124; release &#124; memcheck] | 选择目标版本。                                    |
| -3rd  | ${Code directory}/binarylibs | [binarylibs path]                      | 指定binarylibs路径。该路径必须是绝对路径。        |
| -o  | ${Code directory}/output | [output path]                      | 指定最终编译结果的输出路径。        |
| -pkg  | 请勿使用此选项。             | -                                      | 将代码编译结果压缩至安装包。                      |

> **注意** 
>
> - **-m [debug | release | memcheck]**表示有三个目标版本可以选择：
>    - **release**：生成release版本的二进制程序。此版本编译时，通过配置GCC高级优化选项，去除内核调试代码。此选项通常在生成环境或性能测试环境中使用。
>    - **debug**：表示生成debug版本的二进制程序。此版本编译时，增加了内核代码调试功能，一般用于开发自测环境。
>    - **memcheck**：表示生成memcheck版本的二进制程序。此版本编译时，在debug版本的基础上增加了ASAN功能，用于定位内存问题。
> - **-3rd [binarylibs path]**为**binarylibs**的路径。默认设置为当前代码文件夹下存在**binarylibs**，因此如果**binarylibs**被移至**CM**中，或者在**CM**中创建了到**binarylibs**的软链接，则不需要指定此参数。但请注意，这样做的话，该文件很容易被**git clean**命令删除。
> - **-o [output path]**为**output**的路径。默认设置为当前代码文件夹下的**output**，指定路径后，**编译时会清理该文件夹下的所有文件**，使用时请务必确认好。
> - 该脚本中的每个选项都有一个默认值。选项数量少，依赖简单。因此，该脚本易于使用。如果实际需要的参数值与默认值不同，请根据实际情况配置。

现在你已经知晓build.sh的用法，只需使用如下命令即可编译CM。

``` shell
[user@linux CM]$ sh build.sh -m [debug | release | memcheck] -3rd [binarylibs path]
```

举例： 

```shell
[user@linux CM]$ sh build.sh       # 编译安装release版本的openGauss。需代码目录下有binarylibs或者其软链接，否则将会失败。
[user@linux CM]$ sh build.sh -m debug -3rd /sda/binarylibs    # 编译安装debug版本的openGauss
```

编译后的软件安装路径为：**/sda/CM/output**

编译后的二进制文件路径为：**/sda/CM/output/bin**


##### 使用命令编译代码

1.配置环境变量

   ```shell
   export BINARYLIBS=________    # Path of the binarylibs file
   export GCC_PATH=$BINARYLIBS/buildtools/gcc10.3/
   export CC=$GCC_PATH/gcc/bin/gcc
   export CXX=$GCC_PATH/gcc/bin/g++
   export LD_LIBRARY_PATH=$GCC_PATH/gcc/lib64:$GCC_PATH/isl/lib:$GCC_PATH/mpc/lib/:$GCC_PATH/mpfr/lib/:$GCC_PATH/gmp/lib/:$LD_LIBRARY_PATH
   export PATH=$GCC_PATH/gcc/bin:$PATH

   ```
  
 3.准备好依赖的三方组件。
 
 位于CM代码根目录的common_lib/dcc文件夹用来存放CM依赖的三方组件**DCC**
 
 **DCC动态库获取方式参见** [附:DCC动态库获取](#附:DCC动态库获取)
 
 准备好后的目录结构如下：
 
 ```
 [user@linux CM]$ tree common_lib/dcc/
 common_lib/dcc/
├── include
│   └── dcc_interface.h
└── lib
    ├── libdcc.so
    ├── libdcf.so
    └── libgstor.so

2 directories, 4 files
 ```
 
   
4.选择一个版本进行编译配置。
   
 - **cmake:**
 **新建编译目录**
 
    ```
    mkdir dist
    cd dist
    ```
 
   **debug**版本：

   ```
   cmake .. -DCMAKE_INSTALL_PREFIX=`pwd`/../output/ -DCMAKE_BUILD_TYPE=Debug
   ```

   **release**版本

   ```
   cmake .. -DCMAKE_INSTALL_PREFIX=`pwd`/../output/ -DCMAKE_BUILD_TYPE=Release
   ```

   **memcheck**版本：

   ```
   cmake .. -DCMAKE_INSTALL_PREFIX=`pwd`/../output/ -DENABLE_MEMCHECK=ON
   ```

5.执行以下命令编译CM：

 - **cmake:**
   ```
   [user@linux CM]$ make -sj
   [user@linux CM]$ make install -sj
   ```

- **makefile:**
   **debug**版本：

   ```
   [user@linux CM]$ make -sj
   [user@linux CM]$ make install -sj
   ```

   **release**版本：

   ```
   [user@linux CM]$ make BUILD_TYPE=Release -sj
   [user@linux CM]$ make BUILD_TYPE=Release install -sj
   ```

   **memcheck**版本：

   ```
   [user@linux CM]$ make ENABLE_MEMCHECK=ON -sj
   [user@linux CM]$ make ENABLE_MEMCHECK=ON install -sj
   ```

- 编译后的软件安装路径为**CM/output**。

- 编译后的二进制文件存放路径为：**CM/output/bin**。



### 编译安装包 

请先阅读[使用build.sh编译](#使用build.sh编译)章节，了解build.sh的用法，以及如何使用该脚本编译CM。

现在，只需添加一个-pkg选项，就可以编译安装包。

```
[user@linux openGauss-server]$ sh build.sh -m [debug | release | memcheck] -3rd [binarylibs path] -pkg
```

举例：

```
sh build.sh -pkg       # 生成release版本的openGauss安装包。需代码目录下有binarylibs或者其软链接，否则将会失败。
sh build.sh -m debug -3rd /sdc/binarylibs -pkg           # 生成debug版本的openGauss安装包
```

- 生成的安装包存放目录：**./output**。


### 附:DCC动态库获取

DCC编译参见DCC仓库README指导，然后将编译结果（即DCC编译成功后include目录和lib目录下的文件）按如下目录拷贝到CM代码根目录的`common_lib`文件夹

 ```
 [user@linux CM]$ tree common_lib/dcc/
 common_lib/dcc/
├── include
│   └── dcc_interface.h
└── lib
    ├── libdcc.so
    ├── libdcf.so
    └── libgstor.so

2 directories, 4 files
 ```


## 安装

### 创建配置文件

在安装带CM的openGauss之前，需要创建clusterconfig.xml配置文件。XML文件包含部署openGauss+CM的服务器信息、安装路径、IP地址以及端口号等。用于告知openGauss、CM如何部署。用户需根据不同场配置对应的XML文件，带CM的安装，除安装配置文件需要添加CM外，其余步骤与opengauss安装完全相同。

下面以一主二备的部署方案为例，说明如何创建带CM的opengauss集群XML配置文件。
以下value取值信息仅为示例，可自行替换。每行信息均有注释进行说明。

```
<?xml version="1.0" encoding="UTF-8"?>
<ROOT>
    <!-- openGauss整体信息 -->
    <CLUSTER>
    <!-- 数据库名称 -->
        <PARAM name="clusterName" value="dbCluster" />
    <!-- 数据库节点名称(hostname) -->
        <PARAM name="nodeNames" value="node1,node2,node3" />
    <!-- 节点IP，与nodeNames一一对应 -->
        <PARAM name="backIp1s" value="192.168.0.11,192.168.0.12,192.168.0.13"/>
    <!-- 数据库安装目录-->
        <PARAM name="gaussdbAppPath" value="/opt/huawei/install/app" />
    <!-- 日志目录-->
        <PARAM name="gaussdbLogPath" value="/var/log/omm" />
    <!-- 临时文件目录-->
        <PARAM name="tmpMppdbPath" value="/opt/huawei/tmp"/>
    <!--数据库工具目录-->
        <PARAM name="gaussdbToolPath" value="/opt/huawei/install/om" />
    <!--数据库core文件目录-->
        <PARAM name="corePath" value="/opt/huawei/corefile"/>
    <!-- openGauss类型，此处示例为单机类型，“single-inst”表示单机一主多备部署形态-->
        <PARAM name="clusterType" value="single-inst"/>
    </CLUSTER>
    <!-- 每台服务器上的节点部署信息 -->
    <DEVICELIST>
        <!-- node1上的节点部署信息 -->
        <DEVICE sn="1000001">
        <!-- node1的hostname -->
            <PARAM name="name" value="node1"/>
        <!-- node1所在的AZ及AZ优先级 -->
            <PARAM name="azName" value="AZ1"/>
            <PARAM name="azPriority" value="1"/>
        <!-- 如果服务器只有一个网卡可用，将backIP1和sshIP1配置成同一个IP -->
            <PARAM name="backIp1" value="192.168.0.11"/>
            <PARAM name="sshIp1" value="192.168.0.11"/>
            
        <!--CM-->
	    <!--CM数据目录-->
            <PARAM name="cmDir" value="/opt/huawei/install/data/cm" />
            <PARAM name="cmsNum" value="1" />
	    <!--CM监听端口-->
            <PARAM name="cmServerPortBase" value="5000" />
            <PARAM name="cmServerlevel" value="1" />
	    <!--CM所有实例所在节点名及监听ip-->
            <PARAM name="cmServerListenIp1" value="192.168.0.11,192.168.0.12,192.168.0.13" />
            <PARAM name="cmServerRelation" value="node1,node2,node3" />
            
	    <!--dbnode-->
	    	<PARAM name="dataNum" value="1"/>
	    <!--DBnode端口号-->
	    	<PARAM name="dataPortBase" value="26000"/>
	    <!--DBnode主节点上数据目录，及备机数据目录-->
	    	<PARAM name="dataNode1" value="/opt/huawei/install/data/db1,node2,/opt/huawei/install/data/db1,node3,/opt/huawei/install/data/db1"/>
	    <!--DBnode节点上设定同步模式的节点数-->
	    	<PARAM name="dataNode1_syncNum" value="0"/>
        </DEVICE>

        <!-- node2上的节点部署信息，其中“name”的值配置为主机名称（hostname） -->
        <DEVICE sn="1000002">
            <PARAM name="name" value="node2"/>
            <PARAM name="azName" value="AZ1"/>
            <PARAM name="azPriority" value="1"/>
            <!-- 如果服务器只有一个网卡可用，将backIP1和sshIP1配置成同一个IP -->
            <PARAM name="backIp1" value="192.168.0.12"/>
            <PARAM name="sshIp1" value="192.168.0.12"/>
            <PARAM name="cmDir" value="/opt/huawei/install/data/cm" />
        </DEVICE>

        <!-- node3上的节点部署信息，其中“name”的值配置为主机名称（hostname） -->
        <DEVICE sn="1000003">
            <PARAM name="name" value="node3"/>
            <PARAM name="azName" value="AZ1"/>
            <PARAM name="azPriority" value="1"/>
            <!-- 如果服务器只有一个网卡可用，将backIP1和sshIP1配置成同一个IP -->
            <PARAM name="backIp1" value="192.168.0.13"/>
            <PARAM name="sshIp1" value="192.168.0.13"/>
            <PARAM name="cmDir" value="/opt/huawei/install/data/cm" />
        </DEVICE>
    </DEVICELIST>
</ROOT>
```

### 初始化安装环境

创建完带CM的openGauss配置文件后，在执行安装前，为了后续能以最小权限进行安装及openGauss管理操作，保证系统安全性，需要运行安装前置脚本gs_preinstall准备好安装用户及环境。

安装前置脚本gs_preinstall可以协助用户自动完成如下的安装环境准备工作：

- 自动设置Linux内核参数以达到提高服务器负载能力的目的。这些参数直接影响数据库系统的运行状态，请仅在确认必要时调整。
- 自动将openGauss配置文件、安装包拷贝到openGauss主机的相同目录下。
- openGauss安装用户、用户组不存在时，自动创建安装用户以及用户组。
- 读取openGauss配置文件中的目录信息并创建，将目录权限授予安装用户。

**注意事项**

- 用户需要检查上层目录权限，保证安装用户对安装包和配置文件目录读写执行的权限。
- xml文件中各主机的名称与IP映射配置正确。
- 只能使用root用户执行gs_preinstall命令。

**操作步骤**

1.以root用户登录待安装带CM的openGauss的任意主机，并按规划创建存放安装包的目录。

   ```
mkdir -p /opt/software/openGauss
chmod 755 -R /opt/software
   ```

   > **说明** 
   >
   > - 不建议把安装包的存放目录规划到openGauss用户的家目录或其子目录下，可能导致权限问题。
   > - openGauss用户须具有/opt/software/openGauss目录的读写权限。

2.将安装包“openGauss-x.x.x-openEULER-64bit.tar.gz”、“openGauss-x.x.x-openEULER-64bit-cm.tar.gz”和配置文件“clusterconfig.xml”都上传至上一步所创建的目录中。

3.在安装包所在的目录下，解压安装包openGauss-x.x.x-openEULER-64bit.tar.gz。安装包解压后，在/opt/software/openGauss目录下自动生成script目录。在script目录下生成gs_preinstall等OM工具脚本。

```
cd /opt/software/openGauss
tar -zxvf openGauss-x.x.x-openEULER-64bit.tar.gz
```

4.进入工具脚本目录。

   ```
cd /opt/software/openGauss/script
   ```

5.如果是openEuler的操作系统，执行如下命令打开performance.sh文件，用#注释sysctl -w vm.min_free_kbytes=112640 &> /dev/null，键入“ESC”键进入指令模式，执行**:wq**保存并退出修改。

```
vi /etc/profile.d/performance.sh
```

6.为确保openssl版本正确，执行预安装前请加载安装包中lib库。执行命令如下，其中*{packagePath}*为用户安装包放置的路径，本示例中为/opt/software/openGauss。

   ```
export LD_LIBRARY_PATH={packagePath}/script/gspylib/clib:$LD_LIBRARY_PATH
   ```


7.为确保成功安装，检查 hostname 与 /etc/hostname 是否一致。预安装过程中，会对hostname进行检查。

8.使用gs_preinstall准备好安装环境。若为共用环境需加入--sep-env-file=ENVFILE参数分离环境变量，避免与其他用户相互影响，ENVFILE为用户自行指定的环境变量分离文件的路径。
   执行如下命令，即采用交互模式执行前置，并在执行过程中自动创建root用户互信和openGauss用户互信：

   ```
./gs_preinstall -U omm -G dbgrp -X /opt/software/openGauss/clusterconfig.xml
   ```

   omm为数据库管理员用户（即运行openGauss的操作系统用户）,dbgrp为运行openGauss的操作系统用户的组名，/opt/software/ openGauss/clusterconfig.xml为openGauss的配置文件路径。执行过程中需要根据提示选择建立互信，并输入root或openGauss用户的密码。

### 执行安装

执行前置脚本准备好openGauss安装环境之后，按照启动安装过程部署CM+openGauss。

**前提条件**

- 已成功执行前置脚本gs_preinstall。
- 所有服务器操作系统和网络均正常运行。
- 用户需确保各个主机上的locale保持一致。

**操作步骤**

1.（可选）检查安装包和openGauss配置文件在规划路径下是否已存在，如果没有，重新执行预安装，确保预安装成功，再执行以下步骤。

2.登录到openGauss的主机，并切换到omm用户。

   ```
su - omm
   ```

   > **说明** 
   >
   > - omm为gs_preinstall脚本中-U参数指定的用户。
   > - 以上述omm用户执行gs_install脚本。否则会报执行错误。

3.使用gs_install安装openGauss。若为环境变量分离的模式安装的集群需要source环境变量分离文件ENVFILE。

   ```
gs_install -X /opt/software/openGauss/clusterconfig.xml
   ```

 /opt/software/openGauss/script/clusterconfig.xml为openGauss配置文件的路径。在执行过程中，用户需根据提示输入数据库的密码，密码具有一定的复杂度，为保证用户正常使用该数据库，请记住输入的数据库密码。

 密码复杂度要求：

   - 长度至少8个字符。	
   - 不能和用户名、当前密码（ALTER）、当前密码的倒序相同。
   - 以下至少包含三类：大写字母（A - Z）、小写字母（a - z）、数字（0 - 9）、其他字符（仅限~!@#$%^&*()-_=+\|[{}];:,<.>/?）。

4.安装执行成功之后，需要手动删除主机root用户的互信，即删除openGauss数据库各节点上的互信文件。

   ```
rm -rf ~/.ssh
   ```

### 卸载openGauss+CM集群

卸载openGauss的过程包括卸载openGauss和清理openGauss服务器环境。

#### **执行卸载**

openGauss提供了卸载脚本，帮助用户卸载openGauss。

**操作步骤**

1.以操作系统用户omm登录数据库主节点。

2.使用gs_uninstall卸载openGauss。

   ```
gs_uninstall --delete-data
   ```

   或者在openGauss中每个节点执行本地卸载。

   ```
gs_uninstall --delete-data -L
   ```

#### **一键式环境清理**

在openGauss卸载完成后，如果不需要在环境上重新部署openGauss，可以运行脚本gs_postuninstall对openGauss服务器上环境信息做清理。openGauss环境清理是对环境准备脚本gs_preinstall所做设置的清理。
**前提条件**

- openGauss卸载执行成功。
- root用户互信可用。
- 只能使用root用户执行gs_postuninstall命令。

**操作步骤**

1.以root用户登录openGauss服务器。

2.查看互信是否建成功，可以互相执行**ssh 主机名**。输入exit退出。

   ```
   plat1:~ # ssh plat2 
   Last login: Tue Jan  5 10:28:18 2016 from plat1 
   plat2:~ # exit 
   logout 
   Connection to plat2 closed. 
   plat1:~ #
   ```

3.进入script路径下。

   ```
   cd /opt/software/openGauss/script
   ```

4.使用gs_postuninstall进行清理。若为环境变量分离的模式安装的集群需要source环境变量分离文件ENVFILE。

   ```
   ./gs_postuninstall -U omm -X /opt/software/openGauss/clusterconfig.xml --delete-user --delete-group
   ```

  或者在openGauss中每个节点执行本地后置清理。

   ```
   ./gs_postuninstall -U omm -X /opt/software/openGauss/clusterconfig.xml --delete-user --delete-group -L
   ```

 omm为运行openGauss的操作系统用户名，/opt/software/openGauss/clusterconfig.xml为openGauss配置文件路径。

若为环境变量分离的模式安装的集群需删除之前source的环境变量分离的env参数unset MPPDB_ENV_SEPARATE_PATH

5.删除各openGauss数据库节点root用户互信。 


## 许可证

[MulanPSL-2.0](http://license.coscl.org.cn/MulanPSL2/)
