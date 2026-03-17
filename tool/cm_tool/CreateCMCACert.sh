#!/bin/bash
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
# Description  : CreateCMCACert.sh
#############################################################################
set -e

activePeriod=$1
if [ "$activePeriod" == "" ]; then
    activePeriod=10950
fi

read -s passwd
certPath=$GAUSSHOME/share/sslcert/cm
if [ ! -f "$certPath/openssl.cnf" ]; then
    echo "CM ssl conf does not exist."
    exit 1
fi
export OPENSSL_CONF=$GAUSSHOME/share/sslcert/gsql/openssl.cnf
if [ ! -f "$OPENSSL_CONF" ]; then
    echo "ssl config file does not exist."
    exit 1
fi

# generate root cert
## cakey.pem
echo "$passwd" | openssl genrsa -aes256 -f4 -passout stdin -out $certPath/cakey.pem 2048
## cacert.pem
echo "$passwd" | openssl req -new -x509 -passin stdin -days $activePeriod -key $certPath/cakey.pem -out $certPath/cacert.pem -subj "/C=CN/ST=NULL/L=NULL/O=NULL/OU=NULL/CN=CA"

# generate server and client cert
for role in "server" "client";
do
    ## key
    echo "$passwd" | openssl genrsa -aes256 -passout stdin -out $certPath/$role.key 2048
    ## csr
    echo "$passwd" | openssl req -new -key $certPath/$role.key -passin stdin -out $certPath/$role.csr -subj "/C=CN/ST=NULL/L=NULL/O=NULL/OU=NULL/CN=$role"
    ## crt
    echo "$passwd" | openssl x509 -req -days $activePeriod -in $certPath/$role.csr -CA $certPath/cacert.pem -CAkey $certPath/cakey.pem -passin stdin -CAcreateserial -out $certPath/$role.crt -extfile $certPath/openssl.cnf
done

# generate server cipher and rand
expect -c "
    spawn cm_ctl encrypt -M server -D $certPath;
    expect {
            \"*password*\" { send \"$passwd\r\"; exp_continue }
    }
"

# generate client cipher and rand
expect -c "
    spawn cm_ctl encrypt -M client -D $certPath;
    expect {
            \"*password*\" { send \"$passwd\r\"; exp_continue }
    }
"
# set the password to null and unset it
passwd=""
unset passwd

# change to readonly
chmod 400 $certPath/*
