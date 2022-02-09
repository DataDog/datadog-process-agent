export PROCESS_AGENT_VERSION=$(packaging/version.sh)
export EBPF=${EBPF:-true}
"source ~/.bashrc"
go get golang.org/x/tools/cmd/gorename
go get golang.org/x/tools/cmd/eg
go get golang.org/x/lint/golint
printenv
(cd packaging; ./apply_branding.sh)
rake ci
(cd packaging; ./build_staging_package.sh)