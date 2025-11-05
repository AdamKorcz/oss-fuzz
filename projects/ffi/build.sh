#!/bin/bash -eu
# Copyright 2025 Google LLC
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

# Build the ffi gem from source with proper instrumentation
cd $SRC/ffi

# Initialize git submodules (libffi is a submodule)
git submodule update --init --recursive --depth 1

# Build the C extension with sanitizer instrumentation
# This ensures the native FFI code is instrumented for coverage
cd $SRC/ffi/ext/ffi_c
ruby extconf.rb
# Use clang for compilation to support sanitizer flags
# Don't remove the vars passed to `make` - they matter
make CC="$CC" CXX="$CXX" CFLAGS="$CFLAGS" CXXFLAGS="$CXXFLAGS"

# Install the gem manually to ensure instrumented extension is used
cd $SRC/ffi
mkdir -p $OUT/ffi-gem/gems/ffi-1.0.0/lib
mkdir -p $OUT/ffi-gem/gems/ffi-1.0.0/ext/ffi_c

# Copy Ruby library files
cp -r lib/* $OUT/ffi-gem/gems/ffi-1.0.0/lib/

# Copy the compiled, instrumented extension
cp ext/ffi_c/ffi_c.so $OUT/ffi-gem/gems/ffi-1.0.0/lib/ 2>/dev/null || \
cp ext/ffi_c/ffi_c.bundle $OUT/ffi-gem/gems/ffi-1.0.0/lib/ 2>/dev/null || true

# Setup gem environment
export GEM_HOME=$OUT/ffi-gem
export GEM_PATH=$OUT/ffi-gem

# Create specifications directory
mkdir -p $GEM_HOME/specifications
cat > $GEM_HOME/specifications/ffi-1.0.0.gemspec << 'EOF'
# -*- encoding: utf-8 -*-
Gem::Specification.new do |s|
  s.name = "ffi"
  s.version = "1.0.0"
  s.require_paths = ["lib"]
  s.files = Dir['lib/**/*']
  s.loaded_from = File.expand_path(__FILE__)
end
EOF

# Sync ruzzy
rsync -avu /install/ruzzy/* $OUT/ffi-gem

# Copy all fuzzing harnesses to $OUT
for fuzz_target_path in $SRC/harnesses/fuzz_*.rb; do
    if [ -f "$fuzz_target_path" ]; then
        fuzzer_name=$(basename "$fuzz_target_path" .rb)
        cp "$fuzz_target_path" $OUT/
        
        # Create wrapper script for each fuzzer
        # The LD_PRELOAD ensures ASan is active for the Ruby process
        # -timeout=-1 avoids ruzzy timeout issue
        cat > $OUT/$fuzzer_name << EOF
#!/usr/bin/env bash
# LLVMFuzzerTestOneInput for fuzzer detection.
this_dir=\$(dirname "\$0")

export GEM_HOME=\$this_dir/ffi-gem
export GEM_PATH=\$this_dir/ffi-gem

ASAN_OPTIONS="allocator_may_return_null=1:detect_leaks=0:use_sigaltstack=0" LD_PRELOAD=\$(ruby -e 'require "ruzzy"; print Ruzzy::ASAN_PATH') ruby \$this_dir/$fuzzer_name.rb \$@ -timeout=-1
EOF
        chmod +x $OUT/$fuzzer_name
    fi
done
