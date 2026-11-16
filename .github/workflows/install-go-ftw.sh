#!/usr/bin/env bash
# Downloads go-ftw (the CRS test runner) from its GitHub release into a
# directory, as ./ftw.
#
# GO_FTW_VERSION selects the release. GH_TOKEN is used by the GitHub CLI.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: .github/workflows/install-go-ftw.sh <directory>

  directory  Where to put the ftw binary, e.g. the crs checkout.
EOF
}

directory="${1:-}"
if [ -z "${directory}" ]; then
  usage >&2
  exit 2
fi
: "${GO_FTW_VERSION:?GO_FTW_VERSION has to name the go-ftw release}"

cd "${directory}"

# ftw runs on the runner, so its operating system and architecture decide the
# asset. Asking the runner keeps this from drifting apart from the runs-on
# mapping, and a platform with no release fails here rather than on the first
# exec.
case "$(uname -s)" in
Linux) os="linux" ;;
Darwin) os="darwin" ;;
*)
  echo "No go-ftw release for runner operating system $(uname -s)" >&2
  exit 1
  ;;
esac

case "$(uname -m)" in
x86_64) arch="amd64" ;;
aarch64 | arm64) arch="arm64" ;;
*)
  echo "No go-ftw release for runner architecture $(uname -m)" >&2
  exit 1
  ;;
esac

# The release CDN resets connections now and then. Download to a file so a
# truncated transfer fails here instead of reaching tar, and retry it.
archive="ftw_${GO_FTW_VERSION}_${os}_${arch}.tar.gz"
for attempt in 1 2 3; do
  if gh release download -R coreruleset/go-ftw "v${GO_FTW_VERSION}" \
    -p "${archive}" --clobber; then
    break
  fi
  if [ "${attempt}" -eq 3 ]; then
    echo "Giving up on ${archive} after ${attempt} attempts"
    exit 1
  fi
  delay=$((attempt * 5))
  echo "Download failed, retrying in ${delay} seconds"
  sleep "${delay}"
done
tar -xzf "${archive}" ftw
rm "${archive}"
