#!/usr/bin/env bash
curl --user ${CIRCLE_TOKEN}: \
       --request POST \
       --form revision=${CURRENT_GIT_REVISION}\
       --form config=@config.yml \
       --form notify=false \
       https://circleci.com/api/v1.1/project/github/DataDog/datadog-process-agent/tree/${CURRENT_GIT_BRANCH}
