#!/bin/bash -eu
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

if [ $SANITIZER == "coverage" ]; then
	exit 0
fi

export LDFLAGS="${CFLAGS}"
./configure --enable-ctrls
make -j$(nproc) V=1


# Modify a few variables to avoid double declarations
sed 's/int main(/int main2(/g' -i $SRC/proftpd/src/ftpdctl.c
sed 's/main_server/main_server2/g' -i $SRC/proftpd/src/dirtree.c
sed '61d' -i $SRC/proftpd/src/main.c
sed 's/session_t session/session_t session2/g' -i $SRC/proftpd/src/main.c
sed 's/is_master/is_master2/g' -i $SRC/proftpd/src/main.c
sed 's/int main(/int main2(/g' -i $SRC/proftpd/src/main.c

# Compile modified files
export NEW_FLAG="${CC} ${CFLAGS} -DHAVE_CONFIG_H -DLINUX  -I. -I./include"
$NEW_FLAG -c src/main.c -o src/main.o
$NEW_FLAG -c src/dirtree.c -o src/dirtree.o
$NEW_FLAG -c src/ftpdctl.c -o src/ftpdctl.o

find . -name "*.o" -exec ar rcs fuzz_lib.a {} \;

# Build fuzzer
$NEW_FLAG -c $SRC/fuzzer.c -o fuzzer.o
$CC $CXXFLAGS $LIB_FUZZING_ENGINE fuzzer.o -o $OUT/fuzzer \
        src/scoreboard.o \
        fuzz_lib.a \
	-L/src/proftpd/lib \
	-lsupp -lcrypt -pthread

# Build seed corpus
cd $SRC
git clone https://github.com/dvyukov/go-fuzz-corpus
zip $OUT/fuzzer_seed_corpus.zip go-fuzz-corpus/json/corpus/*

