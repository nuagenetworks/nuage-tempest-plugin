#!/bin/bash

PLUGIN_PATH=/opt/stack/nuage-openstack-neutron
DEBUG=1
TRACE=

BLUE='\033[0;94m'
MAGENTA='\033[0;95m'
NC='\033[0m' # No Color

function debug {
    if [[ $DEBUG ]];then
        echo -e "${BLUE}DEBUG: [            ./set_plugin_version] ${*}${NC}"
    fi
}

function trace {
    if [[ $TRACE ]];then
        echo -e "${BLUE}DEBUG: [            ./set_plugin_version] ${*}${NC}"
    fi
}

function magenta {
    echo -e -n "${MAGENTA}"
}

function set_plugin_version {
    version=$1
    from_api_version=$2
    to_api_version=$3
    curdir=$PWD

    debug "Setting plugin branch to $version (from $from_api_version to $to_api_version)"

    if [[ -d $PLUGIN_PATH ]]; then
        cd $PLUGIN_PATH || exit 1
    else
        debug "Error: $PLUGIN_PATH not found!"
        exit 1
    fi
    if [[ ! $(git remote) ]];then
        trace "No git remote found!"
        if git remote add origin git@github.mv.usa.alcatel.com:OpenStack/nuage-openstack-neutron.git; then
            trace "Remote added"
            git_origin=$(git remote)
            debug "git remote is $git_origin"
            new_origin=1
        else
            debug "Adding remote failed. exiting"
            exit 1
        fi
    elif [[ $(git remote| wc -l) == 1 ]]; then
        git_origin=$(git remote)
        debug "git remote is $git_origin"
    else
        trace "Multiple git remotes found:"
        trace "$(git remote)"
        trace "Taking origin"
        git_origin='origin'
    fi
    if [[ $new_origin ]]; then
        git_br=
    else
        git_br=$(git rev-parse --abbrev-ref HEAD)
    fi
    if [[ $git_br != "$version" ]]; then
        magenta
        if git checkout "$version"; then
            trace "git branch is $version"
            trace "$(git log -n 1)"
        else
            trace "git checkout $version failed"
            magenta
            git fetch $git_origin
            git branch --track "$version" $git_origin/"$version"
            trace "Retrying..."
            magenta
            if git checkout "$version"; then
                trace "git branch is $version"
                trace "$(git log -n 1)"
            else
                debug "git checkout $version failed"
                exit 1
            fi
        fi
        if [[ "$from_api_version" != "$to_api_version" ]];then
            debug "Switching api version to $to_api_version"
            if grep base_uri /etc/neutron/plugins/nuage/plugin.ini| grep -v '^#'| grep -q "$to_api_version"; then
                debug "Plugin.ini is already good"
            elif grep base_uri /etc/neutron/plugins/nuage/plugin.ini| grep -v '^#'| grep -q "$from_api_version"; then
                if sudo -S sed -i "s/\/nuage\/api\/$from_api_version/\/nuage\/api\/$to_api_version/g" /etc/neutron/plugins/nuage/plugin.ini; then
                    debug "Plugin config updated"
                else
                    debug "Plugin config update FAILED!"
                    exit 1
                fi
            elif grep base_uri /etc/neutron/plugins/nuage/plugin.ini| grep -q -v '^#'; then
                debug "FAIL: Nor 'to' nor 'from' base_uri version found."
                exit 1
            else
                echo -e "\n# --- added content by set_plugin_version.sh ---"| sudo -S tee -a /etc/neutron/plugins/nuage/plugin.ini
                echo "[restproxy]"| sudo -S tee -a /etc/neutron/plugins/nuage/plugin.ini
                echo "base_uri = /nuage/api/$to_api_version"| sudo -S tee -a  /etc/neutron/plugins/nuage/plugin.ini
            fi
        fi
        debug "$(grep base_uri /etc/neutron/plugins/nuage/plugin.ini| grep -v '^#')"
        debug "Restarting neutron"
        sudo -S systemctl restart devstack@q-svc.service
        sleep 5
        debug "Plugin branched to $version"
    else
        debug "Plugin is already branched to $version, nothing to be done"
        debug "$(grep base_uri /etc/neutron/plugins/nuage/plugin.ini| grep -v '^#')"
    fi
    if ! grep base_uri /etc/neutron/plugins/nuage/plugin.ini| grep -v '^#'| grep -q "$to_api_version"; then
        debug "ERROR: plugin version NOT set correctly for $to_api_version"
        cat /etc/neutron/plugins/nuage/plugin.ini
        exit 1
    fi
    cd "$curdir" || exit 1
}

# main

if [[ ! $1 ]]; then
    echo "Use as: ./set_plugin_version.sh <branch-name> <from-api-version> <to-api-version>"
    exit 1
fi

set_plugin_version "$1" "$2" "$3"
