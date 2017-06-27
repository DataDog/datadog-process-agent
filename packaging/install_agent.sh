#!/bin/bash
# (C) Datadog, Inc. 2010-2017
# All rights reserved
# Licensed under Simplified BSD License (see LICENSE)
# Datadog process agent installation script: install and set up the process agent on supported Linux distributions
# using the package manager and Datadog repositories.

set -e
logfile="dd-process-agent-install.log"

# Set up a named pipe for logging
npipe=/tmp/$$.tmp
mknod $npipe p

# Log all output to a log for error checking
tee <$npipe $logfile &
exec 1>&-
exec 1>$npipe 2>&1
trap "rm -f $npipe" EXIT


function on_error() {
    printf "\033[31m$ERROR_MESSAGE
It looks like you hit an issue when trying to install the process agent.

Please send an email to package@datadoghq.com
with the contents of dd-process-agent-install.log and we'll do our very best to help you
solve your problem.\n\033[0m\n"
}
trap on_error ERR

# OS/Distro Detection
# Try lsb_release, fallback with /etc/issue then uname command
KNOWN_DISTRIBUTION="(Debian|Ubuntu|RedHat|CentOS|Fedora|Amazon)"
DISTRIBUTION=$(lsb_release -d 2>/dev/null | grep -Eo $KNOWN_DISTRIBUTION  || grep -Eo $KNOWN_DISTRIBUTION /etc/issue 2>/dev/null || grep -Eo $KNOWN_DISTRIBUTION /etc/Eos-release 2>/dev/null || uname -s)

if [ $DISTRIBUTION = "Darwin" ]; then
    printf "\033[31mThis script does not support installing on Mac.\033[0m\n"
    exit 1;

elif [ -f /etc/debian_version -o "$DISTRIBUTION" == "Debian" -o "$DISTRIBUTION" == "Ubuntu" ]; then
    OS="Debian"
elif [ -f /etc/redhat-release -o "$DISTRIBUTION" == "RedHat" -o "$DISTRIBUTION" == "CentOS" -o "$DISTRIBUTION" == "Fedora" -o "$DISTRIBUTION" == "Amazon" ]; then
    OS="RedHat"
# Some newer distros like Amazon may not have a redhat-release file
elif [ -f /etc/system-release -o "$DISTRIBUTION" == "Amazon" ]; then
    OS="RedHat"
else
    printf "\033]31mThe process agent package does not yet support this platform

    Please contact us at package@datadoghq.com for further assistance. \033[0m\n"
    exit 1;
fi

# Root user detection
if [ $(echo "$UID") = "0" ]; then
    sudo_cmd=''
else
    sudo_cmd='sudo'
fi

# Install the necessary package sources
if [ $OS = "RedHat" ]; then
    echo -e "\033[34m\n* Installing YUM sources for Datadog process agent \n\033[0m"

    UNAME_M=$(uname -m)
    if [ "$UNAME_M"  == "i686" -o "$UNAME_M"  == "i386" -o "$UNAME_M"  == "x86" ]; then
        ARCHI="i386"
    else
        ARCHI="x86_64"
    fi

    if [ $ARCHI = "i386" ]; then
        printf "\033[31mThis script does not support installing on i386 architectures

    Please contact us at package@datadoghq.com for further assistance.\033[0m\n"
        exit 1;
    fi

    # Versions of yum on RedHat 5 and lower embed M2Crypto with SSL that doesn't support TLS1.2
    if [ -f /etc/redhat-release ]; then
        REDHAT_MAJOR_VERSION=$(grep -Eo "[0-9].[0-9]{1,2}" /etc/redhat-release | head -c 1)
    fi
    if [ -n "$REDHAT_MAJOR_VERSION" ] && [ "$REDHAT_MAJOR_VERSION" -le "5" ]; then
        PROTOCOL="http"
    else
        PROTOCOL="https"
    fi

    $sudo_cmd rpm --import $PROTOCOL://s3.amazonaws.com/yum.datadoghq.com/DATADOG_RPM_KEY_E09422B3.public
    $sudo_cmd sh -c "echo -e '[datadog-process]\nname = Datadog, Inc.\nbaseurl = $PROTOCOL://yum.datad0g.com/process/dd-process-agent/x86_64/\nenabled=1\ngpgcheck=1\npriority=1\n$PROTOCOL://yum.datadoghq.com/DATADOG_RPM_KEY_E09422B3.public' > /etc/yum.repos.d/datadog-process.repo"
    printf "\033[34m* Installing the Datadog process agent package\n\033[0m\n"

    # install this to avoid empty /etc/init.d/functions file
    $sudo_cmd yum -y install initscripts

    $sudo_cmd yum -y --disablerepo='*' --enablerepo='datadog-process' install dd-process-agent || $sudo_cmd yum -y install dd-process-agent
elif [ $OS = "Debian" ]; then
    $sudo_cmd apt-key adv --recv-keys --keyserver hkp://keyserver.ubuntu.com:80 C7A7DA52
    printf "\033[34m\n* Installing APT package sources for Datadog Process\n\033[0m\n"
    $sudo_cmd sh -c "echo 'deb http://apt.datad0g.com/ process main' > /etc/apt/sources.list.d/datadog-process.list"
    $sudo_cmd apt-get update

    printf "\033[34m\n* Installing the Datadog process agent package\n\033[0m\n"
    ERROR_MESSAGE="ERROR
Failed to update the sources after adding the Datadog Process repository.
This may be due to any of the configured APT sources failing -
see the logs above to determine the cause.
If the failing repository is Datadog, please contact Datadog support.
*****
"
    $sudo_cmd apt-get install -y --force-yes dd-process-agent
    ERROR_MESSAGE=""
else
    printf "\033[31mYour OS or distribution is not supported by this install script.
Please send an email to package@datadoghq.com and we'll do our very best to help you
solve your problem.\n\033[0m\n"
    exit 1;
fi

# Check the configuration file we need exists
if [ -e /etc/dd-agent/dd-process-agent.ini ]; then
    printf "\033[34m\n* Configuration file /etc/dd-agent/dd-process-agent.ini already exists. Keeping the old configuration file.\033[0m\n"
elif [ -e /etc/dd-agent/dd-process-agent.ini.example ]; then
    printf "\033[34m\n* Detected /etc/dd-agent/dd-process-agent.ini.example. Trying to automatically convert it to dd-process-agent.ini by checking environment variables...\033[0m\n\n"
    # Check if the DD_API_KEY environment variable exists. If so, we populate the config file with that
    # otherwise, warn on that
    if [[ ! -z $DD_API_KEY ]]; then
        printf "\033[32m* The API key is set. You could always change it by editing /etc/dd-agent/dd-process-agent.ini file
    \033[0m"
        $sudo_cmd sh -c 'sed "s/sample_apikey/$DD_API_KEY/" /etc/dd-agent/dd-process-agent.ini.example > /etc/dd-agent/dd-process-agent.ini'
        export host_name=$(hostname)
        $sudo_cmd sh -c 'sed -i "s/sample_hostname/$host_name/" /etc/dd-agent/dd-process-agent.ini'
    else
        printf "\033[31m* The environment variable DD_API_KEY is missing, you need to manually add the API key by editing /etc/dd-agent/dd-process-agent.ini file

After that, the agent is ready to run.

Logs for the agent can be found under /var/log/dd-process-agent.log

To start the agent, run:

    sudo /etc/init.d/dd-process-agent start

And to stop it:

    sudo /etc/init.d/dd-process-agent stop

    \033[0m"
        $sudo_cmd mv /etc/dd-agent/dd-process-agent.ini.example /etc/dd-agent/dd-process-agent.ini
	exit 1;
    fi
else
    printf "\033[31m
We could not locate the configuration file /etc/dd-agent/dd-process-agent.ini.

Please contact us at package@datadoghq.com for further assistance.\033[0m\n"
    exit 1;
fi

# echo some instructions and exit
printf "\033[32m

Your agent is successfully installed and ready to run.

Logs for the agent can be found under /var/log/dd-process-agent.log

To start the agent, run:

    sudo /etc/init.d/dd-process-agent start

And to stop it:

    sudo /etc/init.d/dd-process-agent stop

\033[0m"
