# Justfile for kodegend cross-platform verification
# Targets from .devcontainer: x86_64-pc-windows-gnu, x86_64-apple-darwin

# Docker cache volumes for faster builds
CARGO_CACHE_VOLUME := "kodegend-cargo-cache"
TARGET_CACHE_VOLUME := "kodegend-target-cache"

# Create cache volumes (one-time setup)
create-cache-volumes:
    @echo "Creating Docker cache volumes..."
    @docker volume create {{CARGO_CACHE_VOLUME}} || true
    @docker volume create {{TARGET_CACHE_VOLUME}} || true
    @echo "✓ Cache volumes ready"

# Check all platforms (run check-macos on host, others in devcontainer)
check-kodegend: create-cache-volumes check-macos check-linux check-windows
    @echo "✓ All platform checks complete"

# Check macOS (run on host - macOS)
check-macos:
    #!/usr/bin/env bash
    set -e
    echo "=== macOS (host) ==="
    cargo check 2>&1
    cargo clippy -- -D warnings 2>&1
    echo "✓ macOS check passed"

# Check Linux (run in devcontainer)
check-linux:
    #!/usr/bin/env bash
    set -e
    echo "=== Linux (devcontainer) ==="

    # Check if we're in devcontainer or need to spawn one
    if [ -f /.dockerenv ] || [ -n "$DEVCONTAINER" ]; then
        # Already in container
        cargo check 2>&1
        cargo clippy -- -D warnings 2>&1
    else
        # Run in devcontainer - mount entire workspace for local path deps
        echo "Running in devcontainer..."
        WORKSPACE_ROOT="$(cd ../.. && pwd)"

        # Build image only if it doesn't exist
        IMAGE_NAME="kodegend-builder"
        if ! docker images | grep -q "$IMAGE_NAME"; then
            echo "Building Docker image..."
            docker build -t $IMAGE_NAME .devcontainer/
        else
            echo "Using existing Docker image (run 'just rebuild-image' to force rebuild)"
        fi

        docker run --rm \
            -v kodegend-cargo-cache:/home/builder/.cargo \
            -v kodegend-target-cache:/cache/target \
            -v "${WORKSPACE_ROOT}":/workspace \
            -w /workspace/packages/kodegend \
            -e CARGO_TARGET_DIR=/cache/target \
            kodegend-builder \
            bash -c "cargo check && cargo clippy -- -D warnings"
    fi
    echo "✓ Linux check passed"

# Check Windows (cross-compile via devcontainer)
check-windows:
    #!/usr/bin/env bash
    set -e
    echo "=== Windows (x86_64-pc-windows-gnu) ==="

    # Check if we're in devcontainer or need to spawn one
    if [ -f /.dockerenv ] || [ -n "$DEVCONTAINER" ]; then
        # Already in container
        cargo check --target x86_64-pc-windows-gnu 2>&1
        cargo clippy --target x86_64-pc-windows-gnu -- -D warnings 2>&1
    else
        # Run in devcontainer - mount entire workspace for local path deps
        echo "Running in devcontainer..."
        WORKSPACE_ROOT="$(cd ../.. && pwd)"

        # Build image only if it doesn't exist
        IMAGE_NAME="kodegend-builder"
        if ! docker images | grep -q "$IMAGE_NAME"; then
            echo "Building Docker image..."
            docker build -t $IMAGE_NAME .devcontainer/
        else
            echo "Using existing Docker image (run 'just rebuild-image' to force rebuild)"
        fi

        docker run --rm \
            -v kodegend-cargo-cache:/home/builder/.cargo \
            -v kodegend-target-cache:/cache/target \
            -v "${WORKSPACE_ROOT}":/workspace \
            -w /workspace/packages/kodegend \
            -e CARGO_TARGET_DIR=/cache/target \
            kodegend-builder \
            bash -c "cargo check --target x86_64-pc-windows-gnu && cargo clippy --target x86_64-pc-windows-gnu -- -D warnings"
    fi
    echo "✓ Windows check passed"

# Rebuild Docker image (force rebuild)
rebuild-image:
    @echo "🔨 Rebuilding Docker image..."
    docker build --no-cache -t kodegend-builder .devcontainer/

