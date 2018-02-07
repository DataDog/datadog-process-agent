
def go_build(program, opts={})
  default_cmd = "go build -a"
  if ENV["INCREMENTAL_BUILD"] then
    default_cmd = "go build -i"
  end
  opts = {
    :cmd => default_cmd,
    :race => false,
    :add_build_vars => true,
    :static => false,
    :os => "",
  }.merge(opts)

  dd = 'main'
  commit = `git rev-parse --short HEAD`.strip
  branch = `git rev-parse --abbrev-ref HEAD`.strip
  if os == "windows"
    date = `date /T `.strip
  else
    date = `date +%FT%T%z`.strip
  end
  goversion = `go version`.strip
  agentversion = ENV["PROCESS_AGENT_VERSION"] || "0.99.0"

  vars = {}
  vars["#{dd}.Version"] = agentversion
  if opts[:add_build_vars]
    vars["#{dd}.BuildDate"] = date
    vars["#{dd}.GitCommit"] = commit
    vars["#{dd}.GitBranch"] = branch
    vars["#{dd}.GoVersion"] = goversion
  end

  ldflags = vars.map { |name, value| "-X '#{name}=#{value}'" }

  cmd = opts[:cmd]
  cmd += ' -race' if opts[:race]
  if os != "windows"
    cmd += ' -tags \'docker kubelet kubeapiserver\''
  else
    cmd += ' -tags \'kubelet\''
  end
  print "cmd"

  if opts[:static]
    # Statically linked builds use musl-gcc for full support
    # of alpine and other machines with different gcc versions.
    ENV['CC'] = '/usr/local/musl/bin/musl-gcc'
    ldflags << '-linkmode external'
    ldflags << '-extldflags \'-static\''
  end
  if ENV['windres'] then
    # first compile the message table, as it's an input to the resource file
    msgcmd = "windmc --target pe-x86-64 -r agent/windows_resources agent/windows_resources/process-agent-msg.mc"
    puts msgcmd
    sh msgcmd

    ver_array = "0.99.0".split(".")
    rescmd = "windres --define MAJ_VER=#{ver_array[0]} --define MIN_VER=#{ver_array[1]} --define PATCH_VER=#{ver_array[2]} "
    rescmd += "-i agent/windows_resources/process-agent.rc --target=pe-x86-64 -O coff -o agent/rsrc.syso"
    sh rescmd

  end
  sh "#{cmd} -ldflags \"#{ldflags.join(' ')}\" #{program}"
  if ENV['SIGN_WINDOWS'] then
    signcmd = "signtool sign /v /t http://timestamp.verisign.com/scripts/timestamp.dll /fd SHA256 /sm /s \"My\" /sha1 ECCDAE36FDCB654D2CBAB3E8975AA55469F96E4C process-agent.exe"
    sh signcmd
  end
end


def go_lint(path)
  out = `golint #{path}/*.go`
  errors = out.split("\n")
  puts "#{errors.length} linting issues found"
  if errors.length > 0
    puts out
    fail
  end
end

def go_vet(path)
  sh "go vet #{path}"
end

def go_test(path, opts = {})
  cmd = 'go test -tags docker'
  filter = ''
  if opts[:coverage_file]
    cmd += " -coverprofile=#{opts[:coverage_file]} -coverpkg=./..."
    filter = "2>&1 | grep -v 'warning: no packages being tested depend on'" # ugly hack
  end
  sh "#{cmd} #{path} #{filter}"
end

# return the dependencies of all the packages who start with the root path
def go_pkg_deps(pkgs, root_path)
  deps = []
  pkgs.each do |pkg|
    deps << pkg
    `go list -f '{{ join .Deps "\\n"}}' #{pkg}`.split("\n").select do |path|
      if path.start_with? root_path
        deps << path
      end
    end
  end
  return deps.sort.uniq
end

def go_fmt(path)
  out = `go fmt #{path}`
  errors = out.split("\n")
  if errors.length > 0
    errors.each do |error|
      $stderr.puts error
    end
    fail
  end
end
