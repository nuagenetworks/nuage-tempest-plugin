#!/bin/bash

BASE_PATH=/opt/stack
BASE_PATH_=\\/opt\\/stack
DEBUG=1

BLUE='\033[0;94m'
MAGENTA='\033[0;95m'
NC='\033[0m' # No Color

function debug {
    if [[ $DEBUG ]];then
        echo -e "${BLUE}DEBUG: [            ./set_plugin_version] ${*}${NC}"
    fi
}

function magenta {
    echo -e -n "${MAGENTA}"
}

debug "Installing dependencies..."

curdir=$PWD

for repo in neutron nuage-openstack-neutron; do
    rm -Rf /tmp/$repo
    cp -R $BASE_PATH/$repo /tmp
    cd /tmp/$repo || exit 1
    rm -f upper-constraints.txt  # safety
    cp $BASE_PATH/requirements/upper-constraints.txt .

    sed "s/$BASE_PATH_/\/tmp/g" -i upper-constraints.txt
    debug "$(pwd)$ pip install . -r requirements.txt -c upper-constraints.txt"
    magenta
    if pip install . -c upper-constraints.txt; then
        debug "OK"
    else
        debug "FAILED!"
    fi
done

for lib in pymysql; do
    debug "$(pwd)$ pip install $lib -c upper-constraints.txt"
    magenta
    if pip install $lib -c upper-constraints.txt; then
        debug "OK"
    else
        debug "FAILED!"
    fi
done

cd "$curdir" || exit 1

debug "Done"
