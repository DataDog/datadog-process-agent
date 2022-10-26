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
  system("go install golang.org/x/lint/golint@6edffad5e616")
  system("go install github.com/awalterschulze/goderive@886b66b111a4")
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
  go_build("github.com/StackVista/stackstate-process-agent/cmd/agent", {
    :cmd => "go build -o #{bin}",
    :race => ENV['GO_RACE'] == 'true',
    :add_build_vars => ENV['PROCESS_AGENT_ADD_BUILD_VARS'] != 'false',
    :static => ENV['PROCESS_AGENT_STATIC'] == 'true',
    :bpf => true
  })
end


desc "Run goderive to generate necessary go code"
task :derive do
  sh "go run github.com/awalterschulze/goderive@886b66b111a4 ./..."
end

desc "Run goderive to generate necessary go code (Windows)"
task :derive_win do
  system("go install github.com/awalterschulze/goderive@886b66b111a4")
  system("go generate ./...")
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
  go_test("./...", {
   :static => ENV['PROCESS_AGENT_STATIC'] == 'true',
   :bpf => true
  })
end

desc "Test Datadog Process agent -- cmd"
task :cmdtest do
  cmd = "for /f %f in ('go list ./... ^| find /V \"vendor\"') do go test %f"
  sh cmd
end

desc "Build Stackstate network-tracer agent"
task 'build-network-tracer' do
  bin = "network-tracer"
  go_build("github.com/StackVista/stackstate-process-agent/cmd/network-tracer", {
    :cmd => "go build -o #{bin}",
    :add_build_vars => true,
    :static => ENV['NETWORK_AGENT_STATIC'] == 'true',
    :os => os,
    :bpf => true
  })
end

task :vet do
  go_vet("./...", {
    :static => ENV['PROCESS_AGENT_STATIC'] == 'true',
    :bpf => true
  })
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
  if protocv != 'libprotoc 3.6.1'
    fail "Requires protoc version 3.6.1"
  end
  sh "protoc proto/agent_payload.proto -I $GOPATH/src -I vendor -I proto --gogofaster_out $GOPATH/src"
  sh "protoc proto/agent.proto -I $GOPATH/src -I vendor -I proto --gogofaster_out $GOPATH/src"
end

desc "Datadog Process Agent CI script (fmt, vet, etc)"
task :ci => [:derive, :fmt, :vet, :test, :lint, :build]

task :err do
  system("go install github.com/kisielk/errcheck")
  sh "errcheck github.com/StackVista/stackstate-process-agent"
end

task 'windows-versioned-artifact' do
  process_agent_version = `bash -c "packaging/version.sh"`.strip!
  system("cp process-agent.exe stackstate-process-agent-%s.exe" % process_agent_version)
end

task 'windows-tag-or-commit-artifact' do
  process_agent_version = `bash -c "packaging/commit-or-tag.sh"`.strip!
  sh "echo %s" % process_agent_version
  system("cp process-agent.exe stackstate-process-agent-%s.exe" % process_agent_version)
end