#!/usr/bin/env bash

set -e

function check_program {
    if ! command -v "$1" > /dev/null; then
        echo "ERROR: $1 is not installed."
        exit 1
    fi
}

DOCKER_IMAGE="hub.talkdeskapp.com/golang:1.21-alpine"
WORKSPACE="${WORKSPACE:=$(git rev-parse --show-toplevel)}"

## Tests
unformated_files=$(docker run --rm -v ${WORKSPACE}:${WORKSPACE} -w ${WORKSPACE} ${DOCKER_IMAGE} gofmt -l .)
if [ ! -z "$unformated_files" ]; then
  echo "The following files are unformated: "
  for unformated_file in $unformated_files; do
    echo $unformated_file
  done
  exit 1
fi

echo "Checking requirements."
for program in jq gpg curl shasum git; do
  check_program $program
done

REGISTRY_URL="https://terraform-registry.svc.talkdeskapp.com/talkdesk"
osarchs="darwin/arm64 linux/arm64 linux/amd64 darwin/amd64"
protocols='"5.0" "5.1"'
REPO_NAME_REGEX='terraform-provider-.*'

TF_PROVIDER_REPO="${APP_NAME:-$1}"
if [[ $TF_PROVIDER_REPO =~ $REPO_NAME_REGEX ]]; then
  echo
else
  echo "Wrong repository name '$TF_PROVIDER_REPO'"
  exit 1
fi

VERSION_REGEX='^[0-9]+.[0-9]+.[0-9]+$'
VERSION="${TAG_NAME:-$2}"
VERSION="${VERSION#v}"
if [[ $VERSION =~ $VERSION_REGEX ]]; then
  echo
else
  echo "Wrong version provided '$VERSION'"
  exit 1
fi


TF_PROVIDER_NAME=${TF_PROVIDER_REPO//terraform-provider-/}
OUTPATH="$(mktemp -d)/build/${TF_PROVIDER_NAME}"
OUTPATH_REGISTRY="$(mktemp -d)/registry/${TF_PROVIDER_NAME}"
OUTPATH_REGISTRY_VERSION="${OUTPATH_REGISTRY}/${VERSION}"

REGISTRY_PATH="$(mktemp -d)"
REMOTE_REGISTRY_PATH="${REGISTRY_URL}/${TF_PROVIDER_NAME}/${VERSION}"

gpg --import "${GIT_GPG_PATH}" || true
PGP_KEY_ID="$(gpg --no-tty --list-secret-keys --with-colons | awk -F: '$1 == "sec" {print $5}')"
if [[ -z "$PGP_KEY_ID" ]]; then
  cat > keyconfig <<EOF
     %echo Generating a basic OpenPGP key
     Key-Type: DSA
     Key-Length: 2048
     Subkey-Type: ELG-E
     Subkey-Length: 2048
     Name-Real: KCI
     Name-Comment: Generated automaticaly by KCI on $(date "+%Y-%m-%d %H:%M:%S")
     Name-Email: sre+kci@talkdesk.com
     Expire-Date: 0
     %no-ask-passphrase
     %no-protection
     %commit
     %echo done
EOF

  rm -rf $HOME/.gnupg
  gpg2 --no-tty --batch --gen-key keyconfig
fi

PGP_KEY_ID="$(gpg --no-tty --list-secret-keys --with-colons | awk -F: '$1 == "sec" {print $5}')"
PGP_ARMORED_PUBLIC_KEY=$(gpg --no-tty --armor --export "${PGP_KEY_ID}")


mkdir -p ${OUTPATH_REGISTRY_VERSION}/download

for osarch in $osarchs; do
  echo "Building provider for '$osarch'"
  GOOS="$(echo $osarch | awk -F '/' '{print $1}')"
  GOARCH="$(echo $osarch | awk -F '/' '{print $2}')"

  mkdir -p ${OUTPATH}/${VERSION}/${GOOS}/${GOARCH}/

  docker run --rm \
    -e VERSION="${VERSION}" \
    -e GOOS="${GOOS}" \
    -e GOARCH="${GOARCH}" \
    -v ${OUTPATH}:${OUTPATH} \
    -v ${WORKSPACE}:${WORKSPACE} \
    -w ${WORKSPACE} \
    ${DOCKER_IMAGE} \
    go build -o ${OUTPATH}/${VERSION}/${GOOS}/${GOARCH}/${TF_PROVIDER_REPO} \
      -ldflags "-X Talkdesk/${TF_PROVIDER_REPO}.providerVersion=${VERSION}"

  docker run --rm -v ${OUTPATH_REGISTRY}:${OUTPATH_REGISTRY} -v ${OUTPATH}:${OUTPATH} -w ${OUTPATH}/${VERSION}/${GOOS}/${GOARCH} hub.talkdeskapp.com/kramos/alpine-zip:latest \
    ${OUTPATH_REGISTRY_VERSION}/download/${TF_PROVIDER_REPO}_${VERSION}_${GOOS}_${GOARCH}.zip ${TF_PROVIDER_REPO}

  SHASUM_ZIP=$(shasum -a 256 ${OUTPATH_REGISTRY_VERSION}/download/${TF_PROVIDER_REPO}_${VERSION}_${GOOS}_${GOARCH}.zip | sed "s|${OUTPATH_REGISTRY_VERSION}/download/||")
  echo ${SHASUM_ZIP} >> ${OUTPATH_REGISTRY_VERSION}/SHA256SUMS

  mkdir -p ${OUTPATH_REGISTRY_VERSION}/download/${GOOS}/
  jq -n \
    --argjson protocols "$(echo $protocols | jq -n '[inputs]')" \
    --arg os "${GOOS}" \
    --arg arch "${GOARCH}" \
    --arg filename "${TF_PROVIDER_REPO}_${VERSION}_${GOOS}_${GOARCH}.zip" \
    --arg download_url "${REMOTE_REGISTRY_PATH}/download/${TF_PROVIDER_REPO}_${VERSION}_${GOOS}_${GOARCH}.zip" \
    --arg shasums_url "${REMOTE_REGISTRY_PATH}/SHA256SUMS" \
    --arg shasums_signature_url "${REMOTE_REGISTRY_PATH}/SHA256SUMS.sig" \
    --arg shasum $(echo ${SHASUM_ZIP} | awk '{print $1}') \
    --arg key_id "${PGP_KEY_ID}" \
    --arg ascii_armor "${PGP_ARMORED_PUBLIC_KEY}" \
    --arg trust_signature "" \
    '{"protocols": $protocols, "os": $os, "arch": $arch, "filename": $filename, "download_url": $download_url, "shasums_url": $shasums_url, "shasums_signature_url": $shasums_signature_url, "shasum": $shasum, "signing_keys": {"gpg_public_keys": [{"key_id": $key_id, "ascii_armor": $ascii_armor}]}, "trust_signature", $trust_signature}' \
    > ${OUTPATH_REGISTRY_VERSION}/download/${GOOS}/${GOARCH}

  platforms="${platforms}{\"os\": \"${GOOS}\", \"arch\": \"${GOARCH}\"}"
done

set +e
curl -f -s -L ${REGISTRY_URL}/${TF_PROVIDER_NAME}/versions -o /tmp/versions
set -e

if [[ ! -f "/tmp/versions" ]]; then
    echo '{"versions": []}' > /tmp/versions
fi

cat /tmp/versions | jq \
    --argjson platforms "$(echo $platforms | jq -n '[inputs]')" \
    --argjson protocols "$(echo $protocols | jq -n '[inputs]')" \
    '.versions += [{"version": "'${VERSION}'", "protocols": $protocols, "platforms": $platforms}]' > ${OUTPATH_REGISTRY}/versions

gpg --no-tty --detach-sig --output ${OUTPATH_REGISTRY_VERSION}/SHA256SUMS.sig --sign ${OUTPATH_REGISTRY_VERSION}/SHA256SUMS

mkdir -p ${WORKSPACE}/${OUTPUT_PATH_ARTIFACTS:-k8s-ci/output/artifacts}/${TF_PROVIDER_NAME}
cp -a ${OUTPATH_REGISTRY}/* ${WORKSPACE}/${OUTPUT_PATH_ARTIFACTS:-k8s-ci/output/artifacts}/${TF_PROVIDER_NAME}
