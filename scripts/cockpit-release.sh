#!/usr/bin/env bash
# Build the Cockpit release archives of greyproxy from the checked-out commit.
#
#   scripts/cockpit-release.sh <release name> <version> <output dir>
#
# <release name> names the archives (the tag, e.g. v0.4.5-cockpit.1); <version> is the plain
# upstream semver baked into the binary (0.4.5): greywall parses `greyproxy --version` and treats
# anything else as outdated. The commit line tells fork builds apart.
#
# Two runs on the same commit with the same Go toolchain give byte-identical archives: the build
# time is the commit time, paths are trimmed, VCS stamping is off (untracked files would mark the
# binary modified), and tar/gzip get fixed metadata. Needs GNU tar and coreutils.
set -euo pipefail

if [[ $# -ne 3 ]]; then
    echo "usage: $0 <release name> <version> <output dir>" >&2
    exit 2
fi
release_name=$1
version=$2
output_dir=$3

if [[ ! $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "cockpit-release: version must be plain semver (0.4.5), got '$version'" >&2
    exit 1
fi
if [[ -n $(git status --porcelain --untracked-files=no) ]]; then
    echo "cockpit-release: the working tree has uncommitted changes; build from a clean commit" >&2
    exit 1
fi

commit=$(git rev-parse HEAD)
commit_epoch=$(git log -1 --format=%ct)
build_time=$(TZ=UTC git log -1 --date=format-local:%Y-%m-%dT%H:%M:%SZ --format=%cd)
targets=(linux/amd64 linux/arm64 darwin/arm64)

mkdir -p "$output_dir"
output_dir=$(cd "$output_dir" && pwd)
staging_root=$(mktemp -d)
trap 'rm -rf "$staging_root"' EXIT

for target in "${targets[@]}"; do
    goos=${target%/*}
    goarch=${target#*/}
    archive_base="greyproxy-$release_name-$goos-$goarch"
    staging="$staging_root/$archive_base"
    mkdir -p "$staging"

    echo "cockpit-release: building $goos/$goarch"
    CGO_ENABLED=0 GOOS=$goos GOARCH=$goarch go build -mod=readonly -trimpath -buildvcs=false \
        -ldflags "-s -w -X main.version=$version -X main.buildTime=$build_time -X main.gitCommit=$commit" \
        -o "$staging/greyproxy" ./cmd/greyproxy
    install -m 0644 LICENSE "$staging/LICENSE"
    touch --no-dereference --date="@$commit_epoch" "$staging/greyproxy" "$staging/LICENSE"

    tar --create --directory="$staging" --sort=name --format=gnu \
        --mtime="@$commit_epoch" --owner=0 --group=0 --numeric-owner \
        greyproxy LICENSE |
        gzip -n -9 >"$output_dir/$archive_base.tar.gz"
done

(cd "$output_dir" && sha256sum -- greyproxy-"$release_name"-*.tar.gz >SHA256SUMS)
cat "$output_dir/SHA256SUMS"
