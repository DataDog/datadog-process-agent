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

  # When starting the first time you always need to pull deps
  inv -e deps --verbose --dep-vendor-only

  # Build and test the rtloader
  inv rtloader.clean && inv rtloader.make --python-runtimes \$PYTHON_RUNTIME && inv rtloader.test

  # Build the agent binary
  inv -e agent.build --major-version 2 --python-runtimes \$PYTHON_RUNTIME

  # Build the agent omnibus package
  inv -e agent.omnibus-build --base-dir ~/.omnibus --skip-deps --skip-sign --major-version 2 --python-runtimes \$PYTHON_RUNTIME

  # Clean temporary objects and binary artifacts
  inv agent.clean

  # Switch to python 3
  export PYTHON_RUNTIME=3 && conda activate ddpy\$PYTHON_RUNTIME
---------------------------------------------------------------------------------------

EOF
