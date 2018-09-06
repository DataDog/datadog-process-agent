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
  system("go get github.com/Masterminds/glide")
  system("go get -u github.com/golang/lint/golint")
  system("glide install")
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
  go_build("github.com/StackVista/stackstate-process-agent/agent", {
    :cmd => "go build -a -o #{bin}",
    :race => ENV['GO_RACE'] == 'true',
    :add_build_vars => ENV['PROCESS_AGENT_ADD_BUILD_VARS'] != 'false',
    :static => ENV['PROCESS_AGENT_STATIC'] == 'true',
    :os => os,
    :bpf => ENV['EBPF'] == 'true'
  })
end

# Deprecated, should go away once we are fully merged into dd-agent
desc "DEPRECATED: Build Datadog Process agent for dd-process-agent pkg release"
task :build_ddpkg do
  go_build("github.com/StackVista/stackstate-process-agent/agent", {
    :cmd => "go build -a -o dd-process-agent",
    :race => ENV['GO_RACE'] == 'true',
    :add_build_vars => ENV['PROCESS_AGENT_ADD_BUILD_VARS'] != 'false',
    :static => ENV['PROCESS_AGENT_STATIC'] == 'true'
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
  go_build("github.com/StackVista/stackstate-process-agent/agent", :cmd=> "go build -i -o $GOPATH/bin/#{bin}")
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

desc "Run Datadog Process agent"
task :run do
  ENV['DD_PROCESS_AGENT_ENABLED'] = 'true'
  sh "./process-agent -config ./agent/process-agent.ini"
end

task :vet do
  sh "go list ./... | grep -v vendor | xargs go vet"
end

task :fmt do
  packages = `go list ./... | grep -v vendor`.split("\n")
  packages.each do |pkg|
    go_fmt(pkg)
  end
end

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

desc "Datadog Process Agent CI script (fmt, vet, etc)"
task :ci => [:deps, :fmt, :vet, :test, :lint, :build]

task :err do
  system("go get github.com/kisielk/errcheck")
  sh "errcheck github.com/StackVista/stackstate-process-agent"
end
