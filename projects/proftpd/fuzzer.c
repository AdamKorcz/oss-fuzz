/*
# Copyright 2021 Google LLC.
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
#include <string.h>
#include <stdlib.h>
#include "json.h"


int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size){
        
	char *new_str = (char *)malloc(size+1);
        if (new_str == NULL){
                return 0;
        }
        memcpy(new_str, data, size);
        new_str[size] = '\0';

	pool *p = NULL;
	if (p == NULL) {
		p = make_sub_pool(NULL);
	}
	init_json();
        
	
	pr_json_object_t *json;

        json = pr_json_object_from_text(p, new_str);
        
	(void) pr_json_object_free(json);
        free(new_str);
	finish_json();
	if (p != NULL) {
		destroy_pool(p);
		p = NULL;
	}
        return 0;
}
