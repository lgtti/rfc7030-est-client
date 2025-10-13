#!/bin/bash
# Build APT package for rfc7030-est-client

set -e

VERSION=${1:-"1.0.0"}
ARCH=${2:-"amd64"}
BUILD_DIR="build-apt"
PACKAGE_NAME="rfc7030-est-client"
PACKAGE_DIR="${BUILD_DIR}/${PACKAGE_NAME}_${VERSION}_${ARCH}"

echo "Building APT package: ${PACKAGE_NAME}_${VERSION}_${ARCH}"

# Clean previous build
rm -rf ${BUILD_DIR}

# Create package structure
mkdir -p ${PACKAGE_DIR}/DEBIAN
mkdir -p ${PACKAGE_DIR}/usr/lib/${PACKAGE_NAME}
mkdir -p ${PACKAGE_DIR}/usr/share/doc/${PACKAGE_NAME}

# Copy control file
cp deploy/apt/control ${PACKAGE_DIR}/DEBIAN/
sed -i "s/Version: 1.0.0/Version: ${VERSION}/" ${PACKAGE_DIR}/DEBIAN/control
sed -i "s/Architecture: amd64/Architecture: ${ARCH}/" ${PACKAGE_DIR}/DEBIAN/control

# Copy scripts
cp deploy/apt/postinst ${PACKAGE_DIR}/DEBIAN/
cp deploy/apt/prerm ${PACKAGE_DIR}/DEBIAN/

# Copy all binaries
cp build/bin/rfc7030-est-client-debian11 ${PACKAGE_DIR}/usr/lib/${PACKAGE_NAME}/
cp build/bin/rfc7030-est-client-debian12 ${PACKAGE_DIR}/usr/lib/${PACKAGE_NAME}/
cp build/bin/rfc7030-est-client-ubuntu2004 ${PACKAGE_DIR}/usr/lib/${PACKAGE_NAME}/
cp build/bin/rfc7030-est-client-ubuntu2204 ${PACKAGE_DIR}/usr/lib/${PACKAGE_NAME}/

# Copy documentation
cp README.md ${PACKAGE_DIR}/usr/share/doc/${PACKAGE_NAME}/
cp LICENSE ${PACKAGE_DIR}/usr/share/doc/${PACKAGE_NAME}/
cp AUTHORS ${PACKAGE_DIR}/usr/share/doc/${PACKAGE_NAME}/


# Copy manufacturer script
mkdir -p ${PACKAGE_DIR}/usr/lib/${PACKAGE_NAME}/scripts/manufacturer
cp scripts/manufacturer/manufacturer.sh ${PACKAGE_DIR}/usr/lib/${PACKAGE_NAME}/scripts/manufacturer/
cp scripts/manufacturer/README.md ${PACKAGE_DIR}/usr/share/doc/${PACKAGE_NAME}/manufacturer-README.md

# Set permissions
chmod 755 ${PACKAGE_DIR}/DEBIAN/postinst
chmod 755 ${PACKAGE_DIR}/DEBIAN/prerm
chmod 755 ${PACKAGE_DIR}/usr/lib/${PACKAGE_NAME}/rfc7030-est-client-*
chmod 755 ${PACKAGE_DIR}/usr/lib/${PACKAGE_NAME}/scripts/manufacturer/manufacturer.sh

# Build package
dpkg-deb --build ${PACKAGE_DIR}

echo "Package built: ${PACKAGE_DIR}.deb"
echo "Package size: $(du -h ${PACKAGE_DIR}.deb | cut -f1)"
