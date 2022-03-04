#!/bin/bash

if [ "${CI_COMMIT_TAG}" == "" ]; then echo "${CI_COMMIT_SHORT_SHA}"; else echo "${CI_COMMIT_TAG}"; fi
