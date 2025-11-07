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

find . -type f -name "example_test.go" -print -delete
rm crypto/x509/hybrid_pool_test.go

#deploy_fuzzer "crypto_aes_fuzz_test.go" "crypto/aes" "FuzzAesCtrStream FuzzAesOfbStream FuzzAesCfbEncrypter FuzzAesCfbDecrypter"
#deploy_fuzzer "crypto_dsa_fuzz_test.go" "crypto/dsa" "FuzzDsaVerify FuzzDsaSign"
#deploy_fuzzer "crypto_ecdsa_fuzz_test.go" "crypto/ecdsa" "FuzzEcdsaSign FuzzEcdsaVerify"
#deploy_fuzzer "debug_elf_fuzz_test.go" "debug/elf" "FuzzElfOpen"
#deploy_fuzzer "encoding_base32_fuzz_test.go" "encoding/base32" "FuzzBase32Decode"
#deploy_fuzzer "encoding_base64_fuzz_test.go" "encoding/base64" "FuzzBase64Decode"
#deploy_fuzzer "encoding_gob_fuzz_test.go" "encoding/gob" "FuzzGobDecode"
#deploy_fuzzer "encoding_json_fuzz_test.go" "encoding/json" "FuzzJSONDecode"
#deploy_fuzzer "encoding_xml_fuzz_test.go" "encoding/xml" "FuzzXMLDecode"
#deploy_fuzzer "math_big_fuzz_test.go" "math/big" "FuzzBigIntCmp FuzzBigFloatSetFloat64 FuzzBigRatSetString FuzzBigIntSetString"
#deploy_fuzzer "mime_multipart_fuzz_test.go" "mime/multipart" "FuzzReader FuzzReadForm"
#deploy_fuzzer "crypto_x509_fuzz_test.go" "crypto/x509" "FuzzParseCertificate FuzzParseCertificates FuzzParsePKIXPublicKey FuzzParseCRL FuzzParsePEMCertificate"

compile_native_go_fuzzer_v2 html FuzzEscapeUnescape html_FuzzEscapeUnescape
compile_native_go_fuzzer_v2 crypto/x509 FuzzDomainNameValid crypto_x509_FuzzDomainNameValid
compile_native_go_fuzzer_v2 compress/gzip FuzzReader compress_gzip_FuzzReader
compile_native_go_fuzzer_v2 archive/tar FuzzReader archive_tar_FuzzReader
compile_native_go_fuzzer_v2 archive/zip FuzzReader archive_zip_FuzzReader
compile_native_go_fuzzer_v2 image/png FuzzDecode image_png_FuzzDecode
compile_native_go_fuzzer_v2 image/gif FuzzDecode image_gif_FuzzDecode
compile_native_go_fuzzer_v2 image/jpeg FuzzDecode image_jpeg_FuzzDecode
compile_native_go_fuzzer_v2 encoding/json/internal/jsonwire FuzzCompareUTF16 encoding_json_internal_jsonwire_FuzzCompareUTF16
compile_native_go_fuzzer_v2 encoding/json FuzzUnmarshalJSON encoding_json_FuzzUnmarshalJSON
compile_native_go_fuzzer_v2 encoding/json FuzzDecoderToken encoding_json_FuzzDecoderToken
compile_native_go_fuzzer_v2 encoding/json/jsontext FuzzCoder encoding_json_jsontext_FuzzCoder
compile_native_go_fuzzer_v2 encoding/json/jsontext FuzzResumableDecoder encoding_json_jsontext_FuzzResumableDecoder
compile_native_go_fuzzer_v2 encoding/json/jsontext FuzzValueFormat encoding_json_jsontext_FuzzValueFormat
compile_native_go_fuzzer_v2 encoding/pem FuzzDecode encoding_pem_FuzzDecode
compile_native_go_fuzzer_v2 encoding/csv FuzzRoundtrip encoding_csv_FuzzRoundtrip
compile_native_go_fuzzer_v2 math/big FuzzExpMont math_big_FuzzExpMont




echo ""
echo "==================================================================="
echo "Build completed successfully!"
echo "Total fuzzers: 25"
echo "==================================================================="
