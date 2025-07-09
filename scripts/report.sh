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

set -eo pipefail

: "${OUTPUT_DIR:=/host/tmp}"

declare options
if [ -n "$CASE_ID" ]; then
	options+=("--case-id $CASE_ID")
fi
if [ "$DEBUG" == "true" ] ; then
	options+=("-v")
fi

sos report -s /host ${options[@]} | tee /tmp/log.txt

tmp_sosreport_file=$(grep 'tar.xz' /tmp/log.txt  | awk '{print $1}')
sosreport_basename=$(basename $tmp_sosreport_file)
export sosreport_file=$OUTPUT_DIR/$sosreport_basename

mv "$tmp_sosreport_file" "$sosreport_file"
chmod 644 "$sosreport_file"

echo "sos report saved to host: /tmp/$sosreport_basename"
