require "./gorake.rb"

def os
    case RUBY_PLATFORM
    when /linux/
      "linux"
    when /darwin/
      "darwin"
    when /x64-mingw32/
      "windows"
    else
      fail 'Unsupported OS'
    end
  end

desc "Setup dependencies"
task :deps do
  system("go get -u github.com/golang/dep/cmd/dep")
  system("go get -u github.com/mailru/easyjson")
  system("go get -u golang.org/x/lint/golint")
  system("dep ensure -v -vendor-only")
end

task :default => [:ci]

desc "Build Datadog Process agent"
task :build do
  case os
  when "windows"
    bin = "process-agent.exe"
  else
    bin = "process-agent"
  end
  go_build("github.com/DataDog/datadog-process-agent/cmd/agent", {
    :cmd => "go build -o #{bin}",
    :race => ENV['GO_RACE'] == 'true',
    :add_build_vars => ENV['PROCESS_AGENT_ADD_BUILD_VARS'] != 'false',
    :static => ENV['PROCESS_AGENT_STATIC'] == 'true',
    :os => os,
    :bpf => ENV['EBPF'] == 'true'
  })
end

desc "Install Datadog Process agent"
task :install do
  case os
  when "windows"
    bin = "process-agent.exe"
  else
    bin = "process-agent"
  end
  go_build("github.com/DataDog/datadog-process-agent/cmd/agent", :cmd=> "go build -i -o $GOPATH/bin/#{bin}")
end

desc "Test Datadog Process agent"
task :test do
  cmd = "go list ./... | grep -v vendor | xargs go test"
  if os != "windows"
    cmd += " -tags 'docker kubelet kubeapiserver'"
  end
  sh cmd
end

desc "Test Datadog Process agent -- cmd"
task :cmdtest do
  cmd = "for /f %f in ('go list ./... ^| find /V \"vendor\"') do go test %f"
  sh cmd
end

desc "Build Datadog network-tracer agent"
task 'build-network-tracer' do
  bin = "network-tracer"
  go_build("github.com/DataDog/datadog-process-agent/cmd/network-tracer", {
    :cmd => "go build -o #{bin}",
    :add_build_vars => true,
    :static => ENV['NETWORK_AGENT_STATIC'] == 'true',
    :os => os,
    :bpf => true
  })
end

desc "Run go vet on code"
task :vet do
  sh "go list ./... | grep -v vendor | xargs go vet"
end

desc "Run go fmt"
task :fmt => ['ebpf:fmt'] do
  packages = `go list ./... | grep -v vendor`.split("\n")
  packages.each do |pkg|
    go_fmt(pkg)
  end
end

desc "Run go lint"
task :lint do
  error = false
  packages = `go list ./... | grep -v vendor`.split("\n")
  packages.each do |pkg|
    puts "golint #{pkg}"
    output = `golint #{pkg}`.split("\n")
    output = output.reject do |line|
      filename = line.split(':')[0]
      filename.end_with? '.pb.go'
    end
    if !output.empty?
      puts output
      error = true
    end
  end
  fail "We have some linting errors" if error
end

desc "Compile the protobuf files for the Process Agent"
task :protobuf do
  protocv = `bash -c "protoc --version"`.strip
  if protocv != 'libprotoc 3.3.0'
    fail "Requires protoc version 3.3.0"
  end
  sh "protoc proto/agent.proto -I $GOPATH/src -I vendor -I proto --gogofaster_out $GOPATH/src"
end

task :easyjson do
  sh "easyjson ebpf/event_common.go"
end

task :codegen => [:protobuf, :easyjson]

desc "Datadog Process Agent CI script (fmt, vet, etc)"
task :ci => [:deps, :fmt, :vet, :test, :lint, 'ebpf:object', :build, 'ebpf:test']

task :err do
  system("go get github.com/kisielk/errcheck")
  sh "errcheck github.com/DataDog/datadog-process-agent"
end

namespace "ebpf" do
  sudo=""
  sh 'docker info >/dev/null 2>&1' do |ok, res|
    if !ok
      sudo = "sudo -E"
    end
  end

  DEBUG=1
  DOCKER_FILE='packaging/Dockerfile-ebpf'
  DOCKER_IMAGE='datadog/tracer-bpf-builder'

  desc "Run tests for eBPF code"
  task :test do
    sh "go list ./... | grep -v vendor | sudo -E PATH=#{ENV['PATH']} GOCACHE=off xargs go test -tags 'linux_bpf'"
  end

  desc "Format ebpf code"
  task :fmt do
    sh "#{sudo} go fmt ebpf/tracer-ebpf.go"
  end

  desc "Build eBPF docker-image"
  task :image do
    sh "#{sudo} docker build -t #{DOCKER_IMAGE} -f #{DOCKER_FILE} ."
  end

  desc "Generate and instal eBPF program via gobindata"
  task :build => ['ebpf:fmt', 'ebpf:image'] do
    cmd = "build"
    if ENV['TEST'] != "true"
      cmd += " install"
    end
    sh "#{sudo} docker run --rm -e DEBUG=#{DEBUG} \
        -e CIRCLE_BUILD_URL=#{ENV['CIRCLE_BUILD_URL']} \
        -v $(pwd):/src:ro \
    -v $(pwd)/ebpf:/ebpf/ \
        --workdir=/src \
        #{DOCKER_IMAGE} \
        make -f ebpf/c/tracer-ebpf.mk #{cmd}"
    sh "#{sudo} chown -R $(id -u):$(id -u) ebpf"
  end

    desc "Build and run dockerized `nettop` command for testing"
    task :nettop => :build do
      sh 'sudo docker build -t "ebpf-nettop" . -f packaging/Dockerfile-nettop'
      sh "sudo docker run \
        --net=host \
        --cap-add=SYS_ADMIN \
        --privileged \
        -v /sys/kernel/debug:/sys/kernel/debug \
        ebpf-nettop"
    end
end
