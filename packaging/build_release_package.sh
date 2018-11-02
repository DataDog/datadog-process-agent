#!/bin/sh
set -e

if [ -z $RELEASE_ON ]; then
	echo "Missing value for RELEASE_ON"
	exit 1
fi

# Import public and private key for debian
echo "$SIGNING_PUBLIC_KEY" | gpg --import
echo "$SIGNING_PRIVATE_KEY" | gpg --import
# Import public and private key for rpm
echo "$RPM_PUBLIC_KEY" | gpg --import
echo "$RPM_SIGNING_KEY" | gpg --import
gpg -K

# build deb and rpm package
cd $WORKSPACE/go/src/github.com/StackVista/stackstate-process-agent/packaging

# Expects gimme to be installed
eval "$(gimme 1.10.1)"

export GOPATH=$WORKSPACE/go
export PATH=$PATH:$GOPATH/bin
export DEBFULLNAME="StackState, Inc"

agent_path="$WORKSPACE/go/src/github.com/StackVista/stackstate-process-agent"


if [ -z ${PROCESS_AGENT_VERSION+x} ]; then
	echo "Missing PROCESS_AGENT_VERSION in environment"
	exit 1;
fi

if [ -z ${PROCESS_AGENT_STAGING+x} ]; then
	echo "Agent version: $PROCESS_AGENT_VERSION"
else
	# Staging builds add build number to versioning
	PROCESS_AGENT_VERSION="$PROCESS_AGENT_VERSION-$BUILD_NUMBER"
	echo "Agent version (staging): $PROCESS_AGENT_VERSION"
fi


echo "Getting dependencies..."

cd $agent_path
go get github.com/Masterminds/glide
glide install

echo "Building binaries..."
PROCESS_AGENT_STATIC=true rake build_ddpkg

mkdir -p "$agent_path/packaging/debian/package/opt/stackstate-process-agent/bin/"
mkdir -p "$agent_path/packaging/debian/package/opt/stackstate-process-agent/run/"
mkdir -p "$agent_path/packaging/rpm/package/opt/stackstate-process-agent/bin/"
mkdir -p "$agent_path/packaging/rpm/package/opt/stackstate-process-agent/run/"

# copy the binary
cp "$agent_path/stackstate-process-agent" "$agent_path/packaging/debian/package/opt/stackstate-process-agent/bin/stackstate-process-agent"
cp "$agent_path/stackstate-process-agent" "$agent_path/packaging/rpm/package/opt/stackstate-process-agent/bin/stackstate-process-agent"

# make debian package using fpm
echo "Building debian package..."
cd $agent_path/packaging/debian
fpm -s dir -t deb -v "$PROCESS_AGENT_VERSION" -n stackstate-process-agent --license="Simplified BSD License" --maintainer="StackState" --vendor "StackState" \
--url="https://www.stackstate.com/" --category Network --description "An agent for collecting and submitting process information to StackState (https://www.stackstate.com/)" \
 -a "amd64" --before-remove stackstate-process-agent.prerm --after-install stackstate-process-agent.postinst --after-upgrade stackstate-process-agent.postup \
 --before-upgrade stackstate-process-agent.preup --deb-init stackstate-process-agent.init -C $agent_path/packaging/debian/package .

deb_package_name=stackstate-process-agent_${PROCESS_AGENT_VERSION}_amd64.deb
# sign the debian package
echo "Signing the deb package $deb_package_name..."
export WORKSPACE
$agent_path/packaging/sign_debian_package

# make rpm package using fpm
echo "Building rpm package..."
cd $agent_path/packaging/rpm
fpm -s dir -t rpm -v "$PROCESS_AGENT_VERSION" -n stackstate-process-agent --license="Simplified BSD License" --maintainer="StackState" --vendor "StackState" \
--url="https://www.stackstate.com/" --category Network --description "An agent for collecting and submitting process information to StackState (https://www.stackstate.com/)" \
 -a "amd64" --rpm-init stackstate-process-agent.init --before-remove stackstate-process-agent.prerm --after-install stackstate-process-agent.postinst --after-upgrade stackstate-process-agent.postup \
 --before-upgrade stackstate-process-agent.preup -C $agent_path/packaging/rpm/package .

# sign the rpm package
cp ./.rpmmacros ~/
rpm_package_name=stackstate-process-agent-${PROCESS_AGENT_VERSION}-1.x86_64.rpm
echo "Signing the rpm package $rpm_package_name..."
$agent_path/packaging/sign_rpm_package

cd $agent_path/packaging/

# release debian package to staging repo
echo "Releasing deb package to staging repo..."
debian_package_name=`exec find . -name *.deb -type f`
echo $GPG_PASSPHRASE | deb-s3 upload --bucket $DEB_S3_BUCKET -c $RELEASE_ON -m main --arch amd64 --sign=$SIGN_KEY_ID --gpg_options="--passphrase-fd 0 --no-tty --digest-algo SHA512" --preserve_versions $debian_package_name

# release rpm package to staging repo
echo "Releasing rpm package to staging repo..."
rpm_package_name=`exec find . -name *.rpm -type f`
mkdir -p ~/stackstate-process-agent/x86_64
cp $rpm_package_name ~/stackstate-process-agent/x86_64
cd ~/stackstate-process-agent/x86_64
createrepo .

s3cmd sync -v ~/stackstate-process-agent s3://$RPM_S3_BUCKET/$RELEASE_ON/
