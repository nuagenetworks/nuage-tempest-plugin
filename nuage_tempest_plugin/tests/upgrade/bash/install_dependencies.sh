#!/bin/bash

BASE_PATH=/opt/stack
BASE_PATH_=\\/opt\\/stack
DEBUG=1
TRACE=

BLUE='\033[0;94m'
MAGENTA='\033[0;95m'
NC='\033[0m' # No Color

function debug {
    if [[ $DEBUG ]];then
        echo -e "${BLUE}DEBUG: [       ./install_dependencies.sh] ${@}${NC}"
    fi
}

function magenta {
    echo -e -n "${MAGENTA}"
}

debug "Installing dependencies..."

PWD=`pwd`

for repo in neutron nuage-openstack-neutron; do
    rm -Rf /tmp/$repo
    cp -R $BASE_PATH/$repo /tmp
    cd /tmp/$repo
    rm -f upper-constraints.txt  # safety
    cp $BASE_PATH/requirements/upper-constraints.txt .

    sed "s/$BASE_PATH_/\/tmp/g" -i upper-constraints.txt
    debug "`pwd`$ pip install . -r requirements.txt -c upper-constraints.txt"
    magenta
    pip install . -c upper-constraints.txt
    if [[ $? == 0 ]];then
        debug "OK"
    else
        debug "FAILED!"
    fi
done

for lib in pymysql; do
    debug "`pwd`$ pip install $lib -c upper-constraints.txt"
    magenta
    pip install $lib -c upper-constraints.txt
    if [[ $? == 0 ]];then
        debug "OK"
    else
        debug "FAILED!"
    fi
done

cd $PWD

debug "Done"
