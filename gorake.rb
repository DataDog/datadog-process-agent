
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
  agentversion = ENV["AGENT_VERSION"] || ENV["PROCESS_AGENT_VERSION"] || "0.99.0"

  # NOTE: This value is currently hardcoded and needs to be manually incremented during release
  winversion = "6.6.0".split(".")

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
    tag_set = 'docker kubelet kubeapiserver' # Default tags for non-windows OSes (e.g. linux)
    tag_set += ' linux_bpf' if opts[:bpf]    # Add BPF if ebpf exists
    tag_set += ' netgo' if opts[:bpf] && opts[:static]
    cmd += " -tags \'#{tag_set}\'"
  end
  print "cmd"

  # NOTE: We currently have issues running eBPF components in statically linked binaries, so in the meantime,
  #       if eBPF is enabled, the binary will be dynamically linked, and will not work in environments without glibc.
  if opts[:static]
    ldflags << '-linkmode external'
    ldflags << '-extldflags \'-static\''
    if opts[:bpf]
      # eBPF will require kernel headers
      # TODO: Further debug this and get eBPF working with musl-based statically linked binaries.
      ENV['CGO_CFLAGS'] = '-I/kernel-headers/include/'
    else
      # Statically linked builds use musl-gcc for full support
      # of alpine and other machines with different gcc versions.
      ENV['CC'] = '/usr/local/musl/bin/musl-gcc'
    end
  end

  if ENV['windres'] then
    resdir = "cmd/agent/windows_resources"
    # first compile the message table, as it's an input to the resource file
    msgcmd = "windmc --target pe-x86-64 -r #{resdir} #{resdir}/process-agent-msg.mc"
    puts msgcmd
    sh msgcmd

    rescmd = "windres --define MAJ_VER=#{winversion[0]} --define MIN_VER=#{winversion[1]} --define PATCH_VER=#{winversion[2]} "
    rescmd += "-i #{resdir}/process-agent.rc --target=pe-x86-64 -O coff -o cmd/agent/rsrc.syso"
    sh rescmd
  end

  # Building the binary
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
  cmd = 'go test'
  if os != "windows"
    cmd += ' -tags \'docker \''
  end
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
