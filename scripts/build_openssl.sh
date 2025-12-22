#!/bin/bash

set -e
set -u

ENABLE_SANITIZERS="${ENABLE_SANITIZERS:-0}"

SAN_CFLAGS_DEFAULT="-fsanitize=address,undefined -fno-omit-frame-pointer -g"
SAN_LDFLAGS_DEFAULT="-fsanitize=address,undefined"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSIONS_FILE="${SCRIPT_DIR}/../build.env"

if [ -f "${VERSIONS_FILE}" ]; then
    # shellcheck source=../build.env
    source "${VERSIONS_FILE}"
else
    echo "ERROR: build.env not found at ${VERSIONS_FILE}"
    exit 1
fi

OPENSSL_URL="https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz"
OPENSSL_DIR="openssl-${OPENSSL_VERSION}"
BUILD_DIR="${SCRIPT_DIR}/openssl-build"
INSTALL_PREFIX="${BUILD_DIR}/install"
DOWNLOAD_DIR="${BUILD_DIR}/downloads"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

echo_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

echo_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_dependencies() {
    echo_info "Checking dependencies..."

    local missing_deps=()

    for cmd in curl tar make perl nm; do
        if ! command -v "$cmd" &> /dev/null; then
            missing_deps+=("$cmd")
        fi
    done

    if [ ${#missing_deps[@]} -ne 0 ]; then
        echo_error "Missing required dependencies: ${missing_deps[*]}"
        echo_error "Please install them and try again."
        exit 1
    fi

    echo_info "All dependencies found."
}

setup_directories() {
    echo_info "Setting up build directories..."
    mkdir -p "${DOWNLOAD_DIR}"
    mkdir -p "${INSTALL_PREFIX}"
}

download_openssl() {
    echo_info "Downloading OpenSSL ${OPENSSL_VERSION}..."

    cd "${DOWNLOAD_DIR}"

    if [ -f "openssl-${OPENSSL_VERSION}.tar.gz" ]; then
        echo_info "OpenSSL tarball already exists, skipping download."
    else
        curl -L -o "openssl-${OPENSSL_VERSION}.tar.gz" "${OPENSSL_URL}"
        echo_info "Download complete."
    fi

    if [ -d "${OPENSSL_DIR}" ]; then
        echo_warn "OpenSSL source directory already exists, removing..."
        rm -rf "${OPENSSL_DIR}"
    fi

    echo_info "Extracting OpenSSL source..."
    tar -xzf "openssl-${OPENSSL_VERSION}.tar.gz"
}

configure_openssl() {
    echo_info "Configuring OpenSSL with minimal PQC-only static build..."

    cd "${DOWNLOAD_DIR}/${OPENSSL_DIR}"

    echo_info "Configuring for static-only libcrypto..."

    if [ "${ENABLE_SANITIZERS}" -eq 1 ]; then
        echo_info "Sanitizers ENABLED for this OpenSSL build"
        export CFLAGS="${SAN_CFLAGS_DEFAULT}"
        export LDFLAGS="${SAN_LDFLAGS_DEFAULT}"
    else
        echo_info "Sanitizers DISABLED for this OpenSSL build"
    fi


    ./Configure \
        --prefix="${INSTALL_PREFIX}" \
        --openssldir="${INSTALL_PREFIX}/ssl" \
        no-shared \
        no-tls no-dtls no-ssl no-quic \
        no-aria no-bf no-blake2 no-camellia no-cast no-chacha no-cmac \
        no-des no-dh no-dsa no-ecdh no-ecdsa no-idea no-md4 no-mdc2 \
        no-ocb no-poly1305 no-rc2 no-rc4 no-rmd160 no-scrypt \
        no-seed no-siphash no-siv no-sm2 no-sm3 no-sm4 no-whirlpool \
        no-ec no-ec2m \
        no-afalgeng no-capieng no-dso no-engine no-legacy no-module \
        no-fips-securitychecks no-fips-post \
        no-cmp no-cms no-comp no-ct \
        no-deprecated no-docs \
        no-gost no-http \
        no-nextprotoneg no-ocsp \
        no-psk no-rfc3779 \
        no-sock no-sm2-precomp no-srp no-srtp \
        no-ssl-trace no-ts no-uplink \
        no-padlockeng no-multiblock no-pinshared no-sse2 \
        || {
            echo_error "Configuration failed!"
            exit 1
        }

    echo_info "Configuration complete."
}

detect_cores() {
    local cores=""
    local os_type=""

    if [[ "${OSTYPE:-}" == "darwin"* ]]; then
        os_type="macos"
    elif [[ "${OSTYPE:-}" == "linux"* ]]; then
        os_type="linux"
    elif [[ "${OSTYPE:-}" == "freebsd"* ]] || [[ "${OSTYPE:-}" == "openbsd"* ]] || [[ "${OSTYPE:-}" == "netbsd"* ]]; then
        os_type="bsd"
    else
        os_type="unknown"
    fi

    case "$os_type" in
        macos)
            cores=$(sysctl -n hw.ncpu 2>/dev/null)
            ;;
        linux)
            cores=$(nproc 2>/dev/null)
            ;;
        bsd)
            cores=$(sysctl -n hw.ncpu 2>/dev/null)
            ;;
        *)
            cores=$(getconf _NPROCESSORS_ONLN 2>/dev/null)
            ;;
    esac

    if ! [[ "$cores" =~ ^[0-9]+$ ]] || [ "$cores" -lt 1 ]; then
        cores=4
    fi

    echo "$cores"
}

build_openssl() {
    echo_info "Building OpenSSL (this may take several minutes)..."

    cd "${DOWNLOAD_DIR}/${OPENSSL_DIR}"

    CORES=$(detect_cores)
    echo_info "Detected ${CORES} CPU cores, building with ${CORES} parallel jobs..."

    make -j"${CORES}"

    echo_info "Build complete."
}

install_openssl() {
    echo_info "Installing OpenSSL to ${INSTALL_PREFIX}..."

    cd "${DOWNLOAD_DIR}/${OPENSSL_DIR}"

    CORES=$(detect_cores)
    echo_info "Installing with ${CORES} parallel jobs..."

    make -j"${CORES}" install_sw

    echo_info "Installation complete."
}

main() {
    echo_info "Starting minimal OpenSSL ${OPENSSL_VERSION} build for PQC..."
    echo_info "Build directory: ${BUILD_DIR}"
    echo_info "ENABLE_SANITIZERS=${ENABLE_SANITIZERS}"

    check_dependencies
    setup_directories
    download_openssl
    configure_openssl
    build_openssl
    install_openssl

    echo_info "Build completed successfully!"
    echo_info "Static library location:"
    if [ -f "${INSTALL_PREFIX}/lib64/libcrypto.a" ]; then
        echo_info "${INSTALL_PREFIX}/lib64/libcrypto.a"
    else
        echo_info "${INSTALL_PREFIX}/lib/libcrypto.a"
    fi
    echo_info "Headers: ${INSTALL_PREFIX}/include/openssl/"
}

main "$@"
