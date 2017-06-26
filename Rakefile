require "./gorake.rb"

desc "Setup dependencies"
task :deps do
  system("go get github.com/Masterminds/glide")
  system("go get -u github.com/golang/lint/golint")
  system("glide install")
end

PACKAGES = %w(
  ./agent
  ./checks
  ./config
  ./model
  ./util
)

task :default => [:ci]

desc "Build Datadog Process agent"
task :build do
  go_build("github.com/DataDog/datadog-process-agent/agent", {
    :cmd => "go build -a -o dd-process-agent",
    :race => ENV['GO_RACE'] == 'true',
    :add_build_vars => ENV['PROCESS_AGENT_ADD_BUILD_VARS'] != 'false'
  })
end

desc "Install Datadog Process agent"
task :install do
  go_build("github.com/DataDog/datadog-process-agent/agent", :cmd=> "go build -i -o $GOPATH/bin/dd-process-agent")
end

desc "Test Datadog Process agent"
task :test do
  PACKAGES.each { |pkg| go_test(pkg) }
end

desc "Test Datadog Process agent"
task :coverage do
  files = []
  i = 1
  PACKAGES.each do |pkg|
    file = "#{i}.coverage"
    files << file
    go_test(pkg, {:coverage_file => file})
    i += 1
  end
  files.select! {|f| File.file? f}

  sh "gocovmerge #{files.join(' ')} >|tests.coverage"
  sh "rm #{files.join(' ')}"

  sh 'go tool cover -html=tests.coverage'
end

desc "Run Datadog Process agent"
task :run do
  ENV['DD_PROCESS_ENABLED'] = 'true'
  sh "./dd-process-agent -config ./agent/process-agent.ini"
end

task :vet do
  PACKAGES.each { |pkg| go_vet(pkg) }
end

task :fmt do
  PACKAGES.each { |pkg| go_fmt(pkg) }
end

task :lint do
  error = false
  PACKAGES.each do |pkg|
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
  sh "protoc proto/agent.proto -I $GOPATH/src -I proto --gogofaster_out $GOPATH/src"
end

# FIXME: Lint all the files and then add lint task here
desc "Datadog Process Agent CI script (fmt, vet, etc)"
task :ci => [:fmt, :vet, :test, :build]

task :err do
  system("go get github.com/kisielk/errcheck")
  sh "errcheck github.com/DataDog/datadog-process-agent"
end
