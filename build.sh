#!/bin/bash
# Build script for yay-friend.
#
# The build itself lives in the Makefile, including how the version label is
# derived. This stays as the familiar entry point and does not keep its own copy
# of the ldflags -- it used to, with VERSION hardcoded to 0.1.0, so every binary
# it produced claimed 0.1.0 no matter what it was built from.

set -e

exec make build "$@"
