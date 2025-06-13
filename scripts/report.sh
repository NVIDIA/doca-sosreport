#!/bin/bash

#  2025 NVIDIA CORPORATION & AFFILIATES
#
#  Licensed under the Apache License, Version 2.0 (the License);
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an AS IS BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

# This script will generate a sos report and a dpf report

# Variables:
# CASE_ID - The case number for the support case (optional)
# DEBUG - Be more verbose (optional)
# HOST - Where the host's root file system is mounted (default: /host)
# OUTPUT_DIR - Where to store the report (default: $HOST/tmp)

set -eo pipefail

# Collect from the host's root file system mounted at HOST. sos only applies
# it in its container mode, which needs both variables and one of the
# container values it knows; --sysroot alone is ignored.
export container=oci
export HOST="${HOST:-/host}"

: "${OUTPUT_DIR:=$HOST/tmp}"

declare options
if [ -n "$CASE_ID" ]; then
	options+=("--case-id $CASE_ID")
fi
if [ "$DEBUG" == "true" ] ; then
	options+=("-v")
fi

# Build the report inside the container instead of on the host (the default
# with HOST set), it is moved to OUTPUT_DIR afterwards.
sos report --tmp-dir /var/tmp ${options[@]} | tee /tmp/log.txt

tmp_sosreport_file=$(grep 'tar.xz' /tmp/log.txt  | awk '{print $1}')
sosreport_basename=$(basename $tmp_sosreport_file)
export sosreport_file=$OUTPUT_DIR/$sosreport_basename

mv "$tmp_sosreport_file" "$sosreport_file"
chmod 644 "$sosreport_file"

if [[ "$sosreport_file" == "$HOST"/* ]]; then
	echo "sos report saved to host: ${sosreport_file#"$HOST"}"
else
	echo "sos report saved to: $sosreport_file"
fi
