#!/bin/bash

# RFC7030 EST Client - Integration Tests Runner
# This script starts the EST server and runs the integration tests

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to cleanup on exit
cleanup() {
    print_status "Cleaning up..."
    if [ ! -z "$SERVER_RUNNING" ]; then
        print_status "Stopping EST server..."
        docker-compose down
    fi
}

# Set trap to cleanup on script exit
trap cleanup EXIT

# Check if we're in the right directory
if [ ! -f "docker-compose.yml" ]; then
    print_error "docker-compose.yml not found. Please run this script from the test/ directory"
    exit 1
fi

# Check if certificates exist
if [ ! -f "config/ca-cert.pem" ] || [ ! -f "config/server-cert.pem" ]; then
    print_error "Certificates not found. Please run generate-certs.sh first"
    exit 1
fi

# Check if integration tests exist
if [ ! -f "../build/bin/rfc7030-est-integration-tests" ]; then
    print_error "Integration tests not found. Please compile them first:"
    print_error "  cd .. && make clean && make integration"
    exit 1
fi

print_status "Starting RFC7030 EST Client Integration Tests"
echo "=================================================="

# Step 1: Stop any existing containers
print_status "Stopping any existing EST server containers..."
docker-compose down 2>/dev/null || true

# Step 2: Build the EST server image
print_status "Building EST server Docker image..."
docker-compose build --no-cache

if [ $? -ne 0 ]; then
    print_error "Failed to build EST server image"
    exit 1
fi

print_success "EST server image built successfully"

# Step 3: Start the EST server
print_status "Starting EST server..."
docker-compose up -d

if [ $? -ne 0 ]; then
    print_error "Failed to start EST server"
    exit 1
fi

SERVER_RUNNING=1
print_success "EST server started successfully"

# Step 4: Wait for server to be ready
print_status "Waiting for EST server to be ready..."
sleep 5

# Check if server is responding
print_status "Checking EST server health..."
for i in {1..10}; do
    if curl -s -k https://localhost:8443/.well-known/est/cacerts > /dev/null 2>&1; then
        print_success "EST server is responding on port 8443"
        break
    fi
    if [ $i -eq 10 ]; then
        print_error "EST server is not responding after 10 attempts"
        print_status "Server logs:"
        docker-compose logs est-server | tail -20
        exit 1
    fi
    print_status "Attempt $i/10: Waiting for server..."
    sleep 2
done

# Step 5: Run integration tests
print_status "Running integration tests..."
echo "=================================================="

cd ../build/bin
export RFC7030_TEST_RESOURCES_FOLDER="../../test/config"
./rfc7030-est-integration-tests

TEST_EXIT_CODE=$?

echo "=================================================="

# Step 6: Show results
if [ $TEST_EXIT_CODE -eq 0 ]; then
    print_success "All integration tests passed! 🎉"
else
    print_warning "Some integration tests failed (exit code: $TEST_EXIT_CODE)"
fi

# Step 7: Show server logs for debugging
print_status "EST server logs (last 20 lines):"
docker-compose -C ../../test logs est-server | tail -20

echo ""
print_status "Integration tests completed!"
print_status "EST server is still running. To stop it, run:"
print_status "  cd test && docker-compose down"

exit $TEST_EXIT_CODE

