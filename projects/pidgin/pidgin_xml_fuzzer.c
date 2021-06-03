/*
# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
*/

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "xmlnode.h"
#include "caps.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char *malicious_xml = (char *)malloc(size + 1);
  if (malicious_xml == NULL) {
    return 0;
  }
  memcpy(malicious_xml, data, size);
  malicious_xml[size] = '\0';

  xmlnode *isc = xmlnode_from_str(malicious_xml, (int)size + 1);
  if (isc != NULL) {
    JabberCapsClientInfo *info = jabber_caps_parse_client_info(isc);
    xmlnode_free(isc);
  }

  free(malicious_xml);
  return 0;
}