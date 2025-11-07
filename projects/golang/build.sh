#!/bin/bash -eu

export GOTOOLCHAIN="local"
export FUZZ_ROOT="github.com/dvyukov/go-fuzz-corpus"

cd $SRC/go/src
rm ./cmd/cgo/internal/testsanitizers/msan_test.go
rm ./cmd/go/internal/modfetch/codehost/git_test.go
rm ./cmd/go/internal/vcweb/vcstest/vcstest_test.go

GOMEMLIMIT=2048MiB ./make.bash

ls /src/go/bin
export GOROOT="/src/go"
export PATH=/src/go/bin:$PATH

NEW_FUZZERS_DIR="$SRC/harnesses"
SRC_DIR="$SRC/go/src"

cd $SRC_DIR
go mod tidy

deploy_fuzzer() {
    local fuzzer_file=$1
    local target_package=$2
    local fuzzer_names=$3
    
    echo ""
    echo "-------------------------------------------------------------------"
    echo "Processing: $target_package"
    echo "-------------------------------------------------------------------"
    
    target_dir="$SRC_DIR/$target_package"
    if [ ! -d "$target_dir" ]; then
        echo "ERROR: Target directory does not exist: $target_dir"
        return 1
    fi
    
    echo "Copying $fuzzer_file to $target_dir/$fuzzer_file"
    cp "$NEW_FUZZERS_DIR/$fuzzer_file" "$target_dir/$fuzzer_file"
    
    temp_suffix=".ossfuzz_backup"
    for existing_test in "$target_dir"/*_test.go; do
        if [ -f "$existing_test" ] && [ "$existing_test" != "$target_dir/$fuzzer_file" ]; then
            mv "$existing_test" "${existing_test}${temp_suffix}"
        fi
    done
    
    for fuzzer_name in $fuzzer_names; do
        echo "Compiling fuzzer: $fuzzer_name"
        
        output_name=$(echo "$fuzzer_name" | sed 's/Fuzz//' | sed 's/\([A-Z]\)/_\L\1/g' | sed 's/^_//' | tr '[:upper:]' '[:lower:]')
        output_name="${target_package//\//_}_${output_name}"
        
        echo "  -> Output: $output_name"
        
        compile_native_go_fuzzer_v2 "$target_package" "$fuzzer_name" "$output_name" || {
            echo "  ✗ Failed to compile $fuzzer_name"
            for backup_file in "$target_dir"/*${temp_suffix}; do
                [ -f "$backup_file" ] && mv "$backup_file" "${backup_file%${temp_suffix}}"
            done
            return 1
        }
    done
    
    for backup_file in "$target_dir"/*${temp_suffix}; do
        [ -f "$backup_file" ] && mv "$backup_file" "${backup_file%${temp_suffix}}"
    done
    
    echo "✓ Completed: $target_package"
}

deploy_fuzzer "crypto_aes_fuzz_test.go" "crypto/aes" "FuzzAesCtrStream FuzzAesOfbStream FuzzAesCfbEncrypter FuzzAesCfbDecrypter"
deploy_fuzzer "crypto_dsa_fuzz_test.go" "crypto/dsa" "FuzzDsaVerify FuzzDsaSign"
deploy_fuzzer "crypto_ecdsa_fuzz_test.go" "crypto/ecdsa" "FuzzEcdsaSign FuzzEcdsaVerify"
deploy_fuzzer "debug_elf_fuzz_test.go" "debug/elf" "FuzzElfOpen"
deploy_fuzzer "encoding_base32_fuzz_test.go" "encoding/base32" "FuzzBase32Decode"
deploy_fuzzer "encoding_base64_fuzz_test.go" "encoding/base64" "FuzzBase64Decode"
deploy_fuzzer "encoding_gob_fuzz_test.go" "encoding/gob" "FuzzGobDecode"
deploy_fuzzer "encoding_json_fuzz_test.go" "encoding/json" "FuzzJSONDecode"
deploy_fuzzer "encoding_xml_fuzz_test.go" "encoding/xml" "FuzzXMLDecode"
deploy_fuzzer "math_big_fuzz_test.go" "math/big" "FuzzBigIntCmp FuzzBigFloatSetFloat64 FuzzBigRatSetString FuzzBigIntSetString"
deploy_fuzzer "mime_multipart_fuzz_test.go" "mime/multipart" "FuzzReader FuzzReadForm"
deploy_fuzzer "crypto_x509_fuzz_test.go" "crypto/x509" "FuzzParseCertificate FuzzParseCertificates FuzzParsePKIXPublicKey FuzzParseCRL FuzzParsePEMCertificate"

echo ""
echo "==================================================================="
echo "Build completed successfully!"
echo "Total fuzzers: 25"
echo "==================================================================="
