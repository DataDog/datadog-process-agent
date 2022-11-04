#!/bin/bash

## This script will activate conda and rvm
## if the source mount env var is valued then we work on a copy of the Agent source code

source /root/.bashrc
#conda activate ddpy${PYTHON_RUNTIME}

if [[ ! -z "${AGENT_SOURCE_MOUNT}" ]]; then
    echo "Agent source mount provided: ${AGENT_SOURCE_MOUNT}"

    if [[ -d ${AGENT_SOURCE_MOUNT} ]]; then

        pidof inotifywait
        if [ $? -ne 0 ]; then
            echo "inotifywait not running"

            echo -e "\nCopying ..."
            mkdir -p ${PROJECT_DIR}
            rsync -a ${AGENT_SOURCE_MOUNT}/ ${PROJECT_DIR}

            echo -e "\n--> Open a new shell with 'make shell', so that this terminal will keep syncing changes\n"

            while inotifywait -r -e modify,create,delete,move ${AGENT_SOURCE_MOUNT}; do
                rsync -av ${AGENT_SOURCE_MOUNT}/ ${PROJECT_DIR}
            done
        else
            echo "inotifywait already running"
        fi

    else
        echo "Mount directory does not exist!"
        exit 1
    fi

fi

cd ${PROJECT_DIR}
source .gitlab-scripts/setup_artifactory.sh


cat << EOF

---------------------------------------------------------------------------------------
Here few helpful commands to get you started (check .gitlab-ci-agent.yml for more):

rake ci

---------------------------------------------------------------------------------------

EOF
