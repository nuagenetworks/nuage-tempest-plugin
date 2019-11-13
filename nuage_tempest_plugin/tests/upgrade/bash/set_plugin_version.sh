#!/bin/bash

PLUGIN_PATH=/opt/stack/nuage-openstack-neutron
DEBUG=1
TRACE=

BLUE='\033[0;94m'
MAGENTA='\033[0;95m'
NC='\033[0m' # No Color

function debug {
    if [[ $DEBUG ]];then
        echo -e "${BLUE}DEBUG: [            ./set_plugin_version] ${@}${NC}"
    fi
}

function trace {
    if [[ $TRACE ]];then
        echo -e "${BLUE}DEBUG: [            ./set_plugin_version] ${@}${NC}"
    fi
}

function magenta {
    echo -e -n "${MAGENTA}"
}

function set_plugin_version {

    version=$1
    curdir=$PWD

    debug "Setting plugin branch to $version..."

    if [[ -d $PLUGIN_PATH ]];then
        cd $PLUGIN_PATH
    else
        debug "Error: $PLUGIN_PATH not found!"
        exit 1
    fi
    if [[ ! `git remote` ]];then
        trace "No git remote found!"
        git remote add origin git@github.mv.usa.alcatel.com:OpenStack/nuage-openstack-neutron.git
        if [[ $? == 0 ]];then
            trace "Remote added"
            git_origin=`git remote`
            debug "git remote is $git_origin"
            new_origin=1
        else
            debug "Adding remote failed. exiting"
            exit 1
        fi
    elif [[ `git remote|wc -l` == 1 ]];then
        git_origin=`git remote`
        debug "git remote is $git_origin"
    else
        trace "Multiple git remotes found:"
        trace `git remote`
        trace "Taking origin"
        git_origin='origin'
    fi
    if [[ $new_origin ]];then
        git_br=
    else
        git_br=`git rev-parse --abbrev-ref HEAD`
    fi
    if [[ $git_br != $version ]];then
        magenta
        git checkout $version
        if [[ $? == 0 ]];then
            trace "git branch is $version"
            trace "`git log -n 1`"
        else
            trace "git checkout $version failed"
            magenta
            git fetch $git_origin
            git branch --track $version $git_origin/$version
            trace "Retrying..."
            magenta
            git checkout $version
            if [[ $? == 0 ]];then
                trace "git branch is $version"
                trace "`git log -n 1`"
            else
                debug "git checkout $version failed"
                exit 1
            fi
        fi
        if [[ $version == *"5"* ]];then
            debug "6.x -> 5.x ($version)"
            if [[ `cat /etc/neutron/plugins/nuage/plugin.ini | grep base_uri | grep -v '^#' | grep v6` ]]; then
                sudo -S sed -i 's/\/nuage\/api\/v6/\/nuage\/api\/v5_0/g' /etc/neutron/plugins/nuage/plugin.ini
                if [[ $? == 0 ]];then
                    debug "plugin config updated"
                else
                    debug "plugin config update FAILED!"
                    exit 1
                fi
            elif [[ `cat /etc/neutron/plugins/nuage/plugin.ini | grep base_uri | grep -v '^#' | grep v5_0` ]]; then
                debug "awkward but plugin.ini is already good"
            else
                sudo -S echo -e "\n# --- added content by set_plugin_version.sh ---" >> /etc/neutron/plugins/nuage/plugin.ini
                sudo -S echo "[restproxy]" >> /etc/neutron/plugins/nuage/plugin.ini
                sudo -S echo "base_uri = /nuage/api/v5_0" >> /etc/neutron/plugins/nuage/plugin.ini
            fi
        else
            debug "5.x -> 6.x ($version)"
            if [[ `cat /etc/neutron/plugins/nuage/plugin.ini | grep base_uri | grep -v '^#' | grep v5_0` ]]; then
                sudo -S sed -i 's/\/nuage\/api\/v5_0/\/nuage\/api\/v6/g' /etc/neutron/plugins/nuage/plugin.ini
                if [[ $? == 0 ]];then
                    debug "plugin config updated"
                else
                    debug "plugin config update FAILED!"
                    exit 1
                fi
            elif [[ `cat /etc/neutron/plugins/nuage/plugin.ini | grep base_uri | grep -v '^#' | grep v6` ]];  then
                debug "awkward but plugin.ini is already good"
            else
                sudo -S echo -e "\n# --- added content by set_plugin_version.sh ---" >> /etc/neutron/plugins/nuage/plugin.ini
                sudo -S echo "[restproxy]" >> /etc/neutron/plugins/nuage/plugin.ini
                sudo -S echo "base_uri = /nuage/api/v6" >> /etc/neutron/plugins/nuage/plugin.ini
            fi
        fi
        debug "`cat /etc/neutron/plugins/nuage/plugin.ini | grep base_uri | grep -v '^#'`"
        debug "Restarting neutron"
        sudo -S systemctl restart devstack@q-svc.service
        trace "Taking a short nap"
        sleep 10
        debug "Plugin branched to $version"
    else
        debug "Plugin is already branched to $version, nothing to be done"
        debug "`cat /etc/neutron/plugins/nuage/plugin.ini | grep base_uri | grep -v '^#'`"
    fi
    if [[ $version == *"5"* ]];then
        if [[ ! `cat /etc/neutron/plugins/nuage/plugin.ini | grep base_uri | grep -v '^#' | grep v5_0` ]]; then
            debug "ERROR: plugin version NOT set correctly for v5_0"
            cat /etc/neutron/plugins/nuage/plugin.ini
            exit 1
        fi
    else
        if [[ ! `cat /etc/neutron/plugins/nuage/plugin.ini | grep base_uri | grep -v '^#' | grep v6` ]]; then
            debug "ERROR: plugin version NOT set correctly for v6"
            cat /etc/neutron/plugins/nuage/plugin.ini
            exit 1
        fi
    fi
    cd $curdir
}

# main

if [[ ! $1 ]]; then
    echo "Use as: ./set_plugin_version.sh <branch-name>"
    exit 1
fi

set_plugin_version $1
