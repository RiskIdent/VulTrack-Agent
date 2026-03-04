#!/bin/bash
# Get version from git tag, fallback to dev

# Check if we're in a git repository
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    echo "dev"
    exit 0
fi

# Try to get version from git describe
git_version=$(git describe --tags --always --dirty 2>/dev/null)

if [ -z "$git_version" ]; then
    echo "dev"
    exit 0
fi

# Remove 'v' prefix if present (e.g., v1.0.0 -> 1.0.0)
git_version=${git_version#v}

# If it contains a dash, it's not a clean tag (e.g., v1.0.0-5-gabc123)
# Extract just the tag part before the first dash
if [[ $git_version == *-* ]]; then
    git_version=$(echo $git_version | cut -d'-' -f1)
fi

echo "$git_version"
