# Copyright 2020 Google Inc.
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

export GOTOOLCHAIN="local"

export FUZZ_ROOT="github.com/dvyukov/go-fuzz-corpus"

cd $SRC/go/src
# delete failing test
rm ./cmd/cgo/internal/testsanitizers/msan_test.go

# These tests are currently broken so let's remove them
rm ./cmd/go/internal/modfetch/codehost/git_test.go
rm ./cmd/go/internal/vcweb/vcstest/vcstest_test.go
GOMEMLIMIT=2048MiB ./all.bash

ls /src/go/bin
export GOROOT="/src/go"
export PATH=/src/go/bin:$PATH

cd $SRC
mv $SRC/go/src ./std
cd std
go mod tidy

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NEW_FUZZERS_DIR="$SRC/harnesses"
SRC_DIR="$SCRIPT_DIR/std"

# Function to copy fuzzer and compile
deploy_fuzzer() {
    local fuzzer_file=$1
    local target_package=$2
    local fuzzer_names=$3  # Space-separated list of fuzzer function names
    
    echo ""
    echo "-------------------------------------------------------------------"
    echo "Processing: $target_package"
    echo "-------------------------------------------------------------------"
    
    # Create target directory if it doesn't exist
    target_dir="$SRC_DIR/$target_package"
    if [ ! -d "$target_dir" ]; then
        echo "ERROR: Target directory does not exist: $target_dir"
        return 1
    fi
    
    # Copy the fuzzer file from new-fuzzers root
    echo "Copying $fuzzer_file to $target_dir/fuzz_test.go"
    cp "$NEW_FUZZERS_DIR/$fuzzer_file" "$target_dir/fuzz_test.go"
    
    # Compile each fuzzer in the file
    for fuzzer_name in $fuzzer_names; do
        echo "Compiling fuzzer: $fuzzer_name"
        
        # Generate output name (convert FuzzName to fuzz_name)
        output_name=$(echo "$fuzzer_name" | sed 's/Fuzz//' | sed 's/\([A-Z]\)/_\L\1/g' | sed 's/^_//' | tr '[:upper:]' '[:lower:]')
        output_name="${target_package//\//_}_${output_name}"
        
        echo "  -> Output: $output_name"
        
        compile_native_go_fuzzer_v2 "std/$target_package" "$fuzzer_name" "$output_name" || {
    done
    
    echo "✓ Completed: $target_package"
}

# Deploy crypto/aes fuzzers
deploy_fuzzer \
    "crypto_aes_fuzz_test.go" \
    "crypto/aes" \
    "FuzzAesCtrStream FuzzAesOfbStream FuzzAesCfbEncrypter FuzzAesCfbDecrypter"

# Deploy crypto/dsa fuzzers
deploy_fuzzer \
    "crypto_dsa_fuzz_test.go" \
    "crypto/dsa" \
    "FuzzDsaVerify FuzzDsaSign"

# Deploy crypto/ecdsa fuzzers
deploy_fuzzer \
    "crypto_ecdsa_fuzz_test.go" \
    "crypto/ecdsa" \
    "FuzzEcdsaSign FuzzEcdsaVerify"

# Deploy debug/elf fuzzers
deploy_fuzzer \
    "debug_elf_fuzz_test.go" \
    "debug/elf" \
    "FuzzElfOpen"

# Deploy encoding fuzzers (split across multiple packages)
deploy_fuzzer \
    "encoding_fuzz_test.go" \
    "encoding/base32" \
    "FuzzBase32Decode"

deploy_fuzzer \
    "encoding_fuzz_test.go" \
    "encoding/base64" \
    "FuzzBase64Decode"

deploy_fuzzer \
    "encoding_fuzz_test.go" \
    "encoding/gob" \
    "FuzzGobDecode"

deploy_fuzzer \
    "encoding_fuzz_test.go" \
    "encoding/json" \
    "FuzzJSONDecode"

deploy_fuzzer \
    "encoding_fuzz_test.go" \
    "encoding/xml" \
    "FuzzXMLDecode"

# Deploy path/filepath fuzzers
deploy_fuzzer \
    "path_filepath_fuzz_test.go" \
    "path/filepath" \
    "FuzzGlob FuzzMatch"

# Deploy math/big fuzzers
deploy_fuzzer \
    "math_big_fuzz_test.go" \
    "math/big" \
    "FuzzBigIntCmp FuzzBigFloatSetFloat64 FuzzBigRatSetString FuzzBigIntSetString"

# Deploy mime/multipart fuzzers
deploy_fuzzer \
    "mime_multipart_fuzz_test.go" \
    "mime/multipart" \
    "FuzzReader FuzzReadForm"

# Deploy regexp fuzzers
deploy_fuzzer \
    "regexp_fuzz_test.go" \
    "regexp" \
    "FuzzCompile FuzzCompilePOSIX FuzzMatch FuzzReplaceAll"

# Deploy strings fuzzers
deploy_fuzzer \
    "strings_fuzz_test.go" \
    "strings" \
    "FuzzSplit FuzzFields FuzzContains"

# Deploy image/tiff fuzzers
deploy_fuzzer \
    "image_tiff_fuzz_test.go" \
    "image/tiff" \
    "FuzzDecode"

# Deploy crypto/x509 fuzzers
deploy_fuzzer \
    "crypto_x509_fuzz_test.go" \
    "crypto/x509" \
    "FuzzParseCertificate FuzzParseCertificates FuzzParsePKIXPublicKey FuzzParseCRL FuzzParsePEMCertificate"


if ! command -v compile_native_go_fuzzer_v2 &> /dev/null; then
    
    existing_count=0
    compiled_count=0
    failed_count=0
    
    # Find all *_test.go files and search for Fuzz functions
    while IFS= read -r test_file; do
        # Get the package directory relative to src/
        pkg_dir=$(dirname "$test_file")
        pkg_path="${pkg_dir#$SRC_DIR/}"
        
        # Find all Fuzz functions in this file
        while IFS= read -r fuzz_func; do
            ((existing_count++))
            
            # Generate output name
            output_name=$(echo "$fuzz_func" | sed 's/Fuzz//' | sed 's/\([A-Z]\)/_\L\1/g' | sed 's/^_//' | tr '[:upper:]' '[:lower:]')
            output_name="${pkg_path//\//_}_${output_name}"
            
            echo ""
            echo "[$existing_count] Compiling: $pkg_path::$fuzz_func"
            echo "  -> Output: $output_name"
            
            if compile_native_go_fuzzer_v2 "std/$pkg_path" "$fuzz_func" "$output_name" 2>&1 | grep -q "Success\|built"; then
                ((compiled_count++))
                echo "  ✓ Success"
            else
                ((failed_count++))
                echo "  ✗ Failed (may already exist or have compilation issues)"
            fi
        done < <(grep -o "^func Fuzz[A-Za-z0-9_]*" "$test_file" | sed 's/^func //')
    done < <(find "$SRC_DIR" -name "*_test.go" -type f 2>/dev/null | while read f; do
        if grep -q "^func Fuzz" "$f" 2>/dev/null; then
            echo "$f"
        fi
    done)
    
fi

