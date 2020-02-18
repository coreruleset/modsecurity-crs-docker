#!/bin/bash -e

source /opt/modsecurity/activate-rules.sh

exec "$@"
