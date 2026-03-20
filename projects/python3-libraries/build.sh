#!/bin/bash -eu
# Copyright 2019 Google Inc.
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

# Ignore memory leaks from python scripts invoked in the build
export ASAN_OPTIONS="detect_leaks=0"
export MSAN_OPTIONS="halt_on_error=0:exitcode=0:report_umrs=0"

# Remove -pthread from CFLAGS, this trips up ./configure
# which thinks pthreads are available without any CLI flags
CFLAGS=${CFLAGS//"-pthread"/}

FLAGS=()
case $SANITIZER in
  address)
    FLAGS+=("--with-address-sanitizer")
    ;;
  memory)
    FLAGS+=("--with-memory-sanitizer")
    # -msan-keep-going is needed to allow MSAN's halt_on_error to function
    FLAGS+=("CFLAGS=-mllvm -msan-keep-going=1")
    ;;
  undefined)
    FLAGS+=("--with-undefined-behavior-sanitizer")
    ;;
esac

export CPYTHON_INSTALL_PATH=$SRC/cpython-install
rm -rf $CPYTHON_INSTALL_PATH
mkdir $CPYTHON_INSTALL_PATH

cd $SRC/cpython
cp $SRC/library-fuzzers/python_coverage.h Python/

# Patch the interpreter to record code coverage
sed -i '1 s/^.*$/#include "python_coverage.h"/g' Python/ceval.c
sed -i 's/case TARGET\(.*\): {/\0\nfuzzer_record_code_coverage(f->f_code, f->f_lasti);/g' Python/ceval.c

./configure "${FLAGS[@]:-}" --prefix=$CPYTHON_INSTALL_PATH

# Build most extension modules statically into libpython so coverage
# instrumentation can see them (shared .so modules are invisible to coverage).
sed -i '0,/^\*shared\*/{s/^\*shared\*/*static*/}' Modules/Setup.stdlib
for mod in _tkinter _curses _curses_panel \
           xxsubtype _xxtestfuzz _testbuffer _testinternalcapi \
           _testcapi _testlimitedcapi _testclinic _testclinic_limited; do
  sed -i "s/^${mod} /#&/" Modules/Setup.stdlib
done

# HACL workaround: clang generates incorrect COMDAT section grouping for
# ASAN-instrumented switch tables in HACL code, causing "relocation refers
# to a discarded section" errors with both GNU ld and lld. Compile HACL
# files without ASAN (the Python hash module wrappers are still instrumented).
HACL_INCLUDES="-I./Modules/_hacl -I./Modules/_hacl/include \
  -D_BSD_SOURCE -D_DEFAULT_SOURCE \
  -I. -I./Include -I./Include/internal -I./Include/internal/mimalloc \
  -DPy_BUILD_CORE_BUILTIN -fPIC"
for hacl_src in Modules/_hacl/Hacl_Hash_*.c Modules/_hacl/Hacl_HMAC.c \
                Modules/_hacl/Hacl_Streaming_HMAC.c Modules/_hacl/Lib_Memzero0.c; do
  [ -f "./$hacl_src" ] || continue
  extra_flags=""
  case "$hacl_src" in
    *Simd128*) extra_flags="-msse4.1 -DHACL_CAN_COMPILE_VEC128" ;;
    *Simd256*) extra_flags="-mavx2 -DHACL_CAN_COMPILE_VEC256" ;;
  esac
  clang -c -O2 -fno-omit-frame-pointer -DNDEBUG $extra_flags \
    $HACL_INCLUDES -o "${hacl_src%.c}.o" "./$hacl_src"
done
touch Modules/_hacl/*.o

make -j$(nproc) LDFLAGS="-Wl,--allow-multiple-definition"
make install

cp -R $CPYTHON_INSTALL_PATH $OUT/
$OUT/cpython-install/bin/python3 -m pip install hypothesis

# Export the libraries needed by statically-linked modules so the fuzzer
# Makefile can link against them (python3-config doesn't include these).
CPYTHON_MODLIBS=$($OUT/cpython-install/bin/python3 -c \
  "import sysconfig; v=sysconfig.get_config_var('MODLIBS') or ''; print(' '.join(v.replace('\\\\','').split()))")
# Flatten to single line and resolve relative .a paths to absolute.
CPYTHON_MODLIBS=$(echo $CPYTHON_MODLIBS | tr -s ' ' | sed "s|Modules/|$SRC/cpython/Modules/|g")
export CPYTHON_MODLIBS
# HACL static archives aren't in MODLIBS — they're linked via MODULE_*_LDFLAGS
# in CPython's Makefile. Export them separately for the fuzzer Makefile.
# Link HACL .o files directly (the .a archives may not exist yet).
export CPYTHON_HACL_LIBS="$(echo $SRC/cpython/Modules/_hacl/*.o)"

cd $SRC/library-fuzzers
make

cp $SRC/library-fuzzers/fuzzer-html $OUT/
cp $SRC/library-fuzzers/html.py $OUT/
zip -j $OUT/fuzzer-html_seed_corpus.zip corp-html/*

cp $SRC/library-fuzzers/fuzzer-xml $OUT/
cp $SRC/library-fuzzers/xml.py $OUT/
zip -j $OUT/fuzzer-xml_seed_corpus.zip corp-xml/*

cp $SRC/library-fuzzers/fuzzer-email $OUT/
cp $SRC/library-fuzzers/email.py $OUT/
zip -j $OUT/fuzzer-email_seed_corpus.zip corp-email/*

cp $SRC/library-fuzzers/fuzzer-httpclient $OUT/
cp $SRC/library-fuzzers/httpclient.py $OUT/
zip -j $OUT/fuzzer-httpclient_seed_corpus.zip corp-httpclient/*

cp $SRC/library-fuzzers/fuzzer-json $OUT/
cp $SRC/library-fuzzers/json.py $OUT/
zip -j $OUT/fuzzer-json_seed_corpus.zip corp-json/*

cp $SRC/library-fuzzers/fuzzer-difflib $OUT/
cp $SRC/library-fuzzers/difflib.py $OUT/
zip -j $OUT/fuzzer-difflib_seed_corpus.zip corp-difflib/*

cp $SRC/library-fuzzers/fuzzer-csv $OUT/
cp $SRC/library-fuzzers/csv.py $OUT/
zip -j $OUT/fuzzer-csv_seed_corpus.zip corp-csv/*

cp $SRC/library-fuzzers/fuzzer-decode $OUT/
cp $SRC/library-fuzzers/decode.py $OUT/
zip -j $OUT/fuzzer-decode_seed_corpus.zip corp-decode/*
cp $SRC/library-fuzzers/fuzzer-decode.dict $OUT/

cp $SRC/library-fuzzers/fuzzer-ast $OUT/
cp $SRC/library-fuzzers/ast.py $OUT/
cp $SRC/library-fuzzers/fuzzer-ast.dict $OUT/
# Use CPython source code as seed corpus
mkdir corp-ast/
find $SRC/cpython -type f -name '*.py' -size -4097c -exec cp {} corp-ast/ \;
zip -j $OUT/fuzzer-ast_seed_corpus.zip corp-ast/*

cp $SRC/library-fuzzers/fuzzer-re $OUT/
cp $SRC/library-fuzzers/re.py $OUT/

cp $SRC/library-fuzzers/fuzzer-zipfile $OUT/
cp $SRC/library-fuzzers/zipfile.py $OUT/

cp $SRC/library-fuzzers/fuzzer-zipfile-hypothesis $OUT/
cp $SRC/library-fuzzers/zipfile_hypothesis.py $OUT/

cp $SRC/library-fuzzers/fuzzer-tarfile $OUT/
cp $SRC/library-fuzzers/tarfile.py $OUT/

cp $SRC/library-fuzzers/fuzzer-tarfile-hypothesis $OUT/
cp $SRC/library-fuzzers/tarfile_hypothesis.py $OUT/

cp $SRC/library-fuzzers/fuzzer-configparser $OUT/
cp $SRC/library-fuzzers/configparser.py $OUT/

cp $SRC/library-fuzzers/fuzzer-tomllib $OUT/
cp $SRC/library-fuzzers/tomllib.py $OUT/

cp $SRC/library-fuzzers/fuzzer-plistlib $OUT/
cp $SRC/library-fuzzers/plist.py $OUT/

# Module fuzzers (ported from C++ to Python).
# Inline fuzz_dp.py into each fuzzer script at build time so the deployed
# fuzzer has no file dependencies beyond cpython-install/.
MODULE_FUZZERS="array binascii codecs collections compression crypto
  csv_module ctypes datetime dbm dis expat ioops json_decode json_encode
  locale mmap operator pickle sqlite3 ssl time unicodedata"
for name in $MODULE_FUZZERS; do
  cp $SRC/library-fuzzers/fuzzer-${name//_/-} $OUT/
  # Concatenate fuzz_dp.py + fuzzer script (with import line removed).
  cat $SRC/library-fuzzers/fuzz_dp.py > $OUT/fuzz_${name}.py
  grep -v '^from fuzz_dp import' $SRC/library-fuzzers/fuzz_${name}.py >> $OUT/fuzz_${name}.py
done

