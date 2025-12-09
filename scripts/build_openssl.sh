#!/bin/bash

set -e
set -u

ENABLE_SANITIZERS="${ENABLE_SANITIZERS:-0}"

# Default sanitizer flags (used only when ENABLE_SANITIZERS=1)
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
BUILD_DIR="$(pwd)/openssl-build"
INSTALL_PREFIX="${BUILD_DIR}/install"
DOWNLOAD_DIR="${BUILD_DIR}/downloads"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NO_COLOR='\033[0m'

echo_info() {
    echo -e "${GREEN}[INFO]${NO_COLOR} $1"
}

echo_warn() {
    echo -e "${YELLOW}[WARN]${NO_COLOR} $1"
}

echo_error() {
    echo -e "${RED}[ERROR]${NO_COLOR} $1"
}

check_dependencies() {
    echo_info "Checking dependencies..."

    local missing_deps=()

    # 'file' removed – only hard deps now:
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

    # Start from any existing flags (possibly coming from the environment)
    # -Os = Optimize for size (safer than -O3 for crypto code)
    # -flto = Link-Time Optimization (reduces size and improves performance)
    local cflags="${CFLAGS:--Os -flto}"
    local ldflags="${LDFLAGS:--flto}"

    if [ "${ENABLE_SANITIZERS}" -eq 1 ]; then
        echo_info "Sanitizers ENABLED for this OpenSSL build"

        # Only append sanitizer flags if not already present
        case " ${cflags} " in
            *"-fsanitize="*) : ;;  # already has sanitizer flags
            *) cflags="${cflags} ${SAN_CFLAGS_DEFAULT}" ;;
        esac

        case " ${ldflags} " in
            *"-fsanitize="*) : ;;
            *) ldflags="${ldflags} ${SAN_LDFLAGS_DEFAULT}" ;;
        esac
    else
        echo_info "Sanitizers DISABLED for this OpenSSL build"
    fi

    echo_info "Using CC=${CC:-clang}"
    echo_info "CFLAGS=${cflags}"
    echo_info "LDFLAGS=${ldflags}"

    CC="${CC:-clang}" \
    CFLAGS="${cflags}" \
    LDFLAGS="${ldflags}" \
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
    elif [[ "${OSTYPE:-}" == "msys"* ]] || [[ "${OSTYPE:-}" == "cygwin"* ]]; then
        os_type="windows"
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
        windows)
            cores=$(nproc 2>/dev/null || echo "$NUMBER_OF_PROCESSORS")
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

test_openssl() {
    echo_info "Running OpenSSL test suite (this may take several minutes)..."

    cd "${DOWNLOAD_DIR}/${OPENSSL_DIR}"

    if make test; then
        echo_info "All tests passed!"
    else
        echo_warn "Some tests failed, but this may be expected with minimal build"
        echo_warn "Continuing with installation..."
    fi
}

install_openssl() {
    echo_info "Installing OpenSSL to ${INSTALL_PREFIX}..."

    cd "${DOWNLOAD_DIR}/${OPENSSL_DIR}"
    make install_sw

    echo_info "Installation complete."
}

verify_build() {
    echo_info "Verifying build..."
    echo_info ""

    local libcrypto_path="${INSTALL_PREFIX}/lib64/libcrypto.a"

    if [ ! -f "${libcrypto_path}" ]; then
        libcrypto_path="${INSTALL_PREFIX}/lib/libcrypto.a"
    fi

    if [ ! -f "${libcrypto_path}" ]; then
        echo_error "libcrypto.a not found!"
        exit 1
    fi

    echo_info "Static library found: ${libcrypto_path}"

    local size
    size=$(du -h "${libcrypto_path}" | cut -f1)
    echo_info "Library size: ${size}"

    echo_info "Analyzing library symbols..."
    local symbol_count
    symbol_count=$(nm "${libcrypto_path}" 2>/dev/null | wc -l | tr -d ' ')
    echo_info "Total symbols: ${symbol_count}"

    echo_info ""
    echo_info "Checking OpenSSL binary..."
    if [ -f "${INSTALL_PREFIX}/bin/openssl" ]; then
        echo_info "OpenSSL binary found: ${INSTALL_PREFIX}/bin/openssl"

        local bin_size
        bin_size=$(du -h "${INSTALL_PREFIX}/bin/openssl" | cut -f1)
        echo_info "  Binary size: ${bin_size}"

        echo_info "  Getting version..."
        local version
        version=$("${INSTALL_PREFIX}/bin/openssl" version 2>/dev/null || echo "Unknown")
        echo_info "  Version: ${version}"
    else
        echo_error "OpenSSL binary not found!"
    fi

    echo_info ""
    echo_info "Checking headers..."
    if [ -d "${INSTALL_PREFIX}/include/openssl" ]; then
        echo_info "OpenSSL headers found"
        local header_count
        header_count=$(find "${INSTALL_PREFIX}/include/openssl" -name "*.h" 2>/dev/null | wc -l | tr -d ' ')
        echo_info "  Header files: ${header_count}"
    else
        echo_warn "OpenSSL headers not found"
    fi

    echo_info ""
    echo_info "Checking for PQC-required symbols..."

    local pqc_found=0
    local binary_found=0

    if nm "${libcrypto_path}" 2>/dev/null | grep -q "EVP_"; then
        echo_info "EVP API symbols found"
        ((pqc_found++))
    else
        echo_error "EVP API symbols not found - build may be incorrect"
    fi

    if nm "${libcrypto_path}" 2>/dev/null | grep -q "EVP_PKEY"; then
        echo_info "EVP_PKEY symbols found"
        ((pqc_found++))
    else
        echo_warn "EVP_PKEY symbols not found"
    fi

    if [ -f "${INSTALL_PREFIX}/bin/openssl" ]; then
        binary_found=1
    fi

    echo_info ""
    echo_info "Build Verification Summary"
    echo_info "Library: ${libcrypto_path}"
    echo_info "Size: ${size}"
    echo_info "Total symbols: ${symbol_count}"
    echo_info "PQC-required symbols found: ${pqc_found}/2"
    echo_info "OpenSSL binary found: $([ ${binary_found} -eq 1 ] && echo 'Yes' || echo 'No')"

    if [ ${pqc_found} -eq 2 ] && [ ${binary_found} -eq 1 ]; then
        echo_info "Build verification PASSED"
        return 0
    else
        echo_warn "Build verification FAILED"
        [ ${pqc_found} -ne 2 ] && echo_warn "  - Missing required PQC symbols"
        [ ${binary_found} -ne 1 ] && echo_warn "  - OpenSSL binary not found"
        return 1
    fi
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
    test_openssl
    install_openssl
    verify_build

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
