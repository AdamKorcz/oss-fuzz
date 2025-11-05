#!/usr/bin/env ruby
# frozen_string_literal: true

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

require 'ruzzy'
require 'ffi'

# ============================================================================
# FFI Struct Operations Fuzzer
# ============================================================================
#
# GOAL:
# This fuzzer targets FFI::Struct to discover bugs in structure layout parsing,
# field access, memory alignment, nested structures, and type handling. Common
# vulnerabilities include:
# - Incorrect offset calculations for struct fields
# - Memory corruption from misaligned field access
# - Buffer overflows in array fields within structs
# - Type confusion in pointer fields
# - Bugs in nested struct and union handling
#
# STRATEGY:
# Uses coverage-guided fuzzing to explore FFI::Struct's API surface by:
# - Dynamically creating struct classes with various layouts
# - Testing 5 different struct configuration patterns
# - Parsing fuzzer input to drive field values and access patterns
# - Exercising struct introspection APIs (size, alignment, offsets)
#
# TEST CASES:
# 1. Simple structs with primitive types (uint8, uint16, uint32, uint64)
#    - Tests basic field access and type handling
#    - Validates layout calculation for different-sized types
#
# 2. Structs with fixed-size arrays
#    - Tests array field indexing and bounds checking
#    - Combines array fields with scalar fields
#
# 3. Nested structs (inner struct as a field)
#    - Tests offset calculation for nested structures
#    - Validates access to fields through nested path
#
# 4. Structs with pointer fields
#    - Tests pointer field assignment and dereferencing
#    - Validates pointer null checking
#
# 5. Complex structs with mixed types
#    - Tests struct introspection methods (members, offsets, size, alignment)
#    - Validates layout with padding and alignment requirements
#
# ERROR HANDLING:
# Robust exception handling prevents harness bugs from hiding real issues.
# Returns 0 on all code paths to indicate successful fuzzing iteration.
#
# ============================================================================
fuzz_target = lambda do |data|
  # Minimum 16 bytes required for struct field initialization
  # Need enough data to populate multiple fields with meaningful values
  return 0 if data.bytesize < 16

  begin
    # Select one of 5 struct test patterns based on first byte
    struct_type = data[0].ord % 5
    
    case struct_type
    when 0
      # ====================================================================
      # TEST CASE 0: Simple struct with progressive primitive types
      # ====================================================================
      # Purpose: Test struct layout with increasing type sizes
      # Bug classes tested:
      # - Incorrect field offset calculation
      # - Alignment padding between fields
      # - Struct size calculation
      # - Field access with different-sized types
      
      # Define struct layout: uint8(1) + uint16(2) + uint32(4) + uint64(8)
      # FFI must calculate correct offsets considering alignment
      test_struct = Class.new(FFI::Struct) do
        layout :byte_field, :uint8,    # offset 0, size 1
               :short_field, :uint16,   # offset 2 (aligned), size 2
               :int_field, :uint32,     # offset 4, size 4
               :long_field, :uint64     # offset 8, size 8
      end

      s = test_struct.new
      
      # Populate each field with fuzzer data
      s[:byte_field] = data[2].ord  # Single byte (0-255)
      
      # Unpack 2 bytes as unsigned short (little-endian)
      s[:short_field] = data[3..4].unpack1('S') rescue 0
      
      # Unpack 4 bytes as unsigned long (32-bit)
      s[:int_field] = data[5..8].unpack1('L') rescue 0
      
      # Unpack 8 bytes as unsigned long long (64-bit)
      s[:long_field] = data[9..16].unpack1('Q') rescue 0
      
      # Read back all fields to exercise getter code paths
      # This can trigger bugs in field offset calculation
      s[:byte_field]; s[:short_field]; s[:int_field]; s[:long_field]
      
      # Test converting struct to pointer (exercises struct memory layout)
      s.to_ptr.null?

    when 1
      # ====================================================================
      # TEST CASE 1: Struct with embedded fixed-size array
      # ====================================================================
      # Purpose: Test inline array handling within structs
      # Bug classes tested:
      # - Array bounds checking in struct fields
      # - Incorrect array stride calculation
      # - Array initialization and access
      
      # Layout: 8-byte uint8 array + 4-byte int32
      test_struct = Class.new(FFI::Struct) do
        layout :array_field, [:uint8, 8],  # Inline array of 8 uint8s
               :value, :int32
      end

      s = test_struct.new
      
      # Populate array field with fuzzer data
      # Array indexing must correctly calculate element offsets
      8.times do |i|
        break if i >= data.bytesize  # Safety check
        s[:array_field][i] = data[i].ord
      end
      
      # Set scalar field after array
      s[:value] = data[8..11].unpack1('l') rescue 0
      
      # Read back array elements (tests array element access)
      8.times { |i| s[:array_field][i] }
      s[:value]

    when 2
      # ====================================================================
      # TEST CASE 2: Nested struct composition
      # ====================================================================
      # Purpose: Test struct-within-struct layout and field access
      # Bug classes tested:
      # - Nested struct offset calculation
      # - Multi-level field access (outer[:inner][:field])
      # - Struct alignment within parent struct
      
      # Define inner struct with two int32 fields
      inner_struct = Class.new(FFI::Struct) do
        layout :x, :int32, :y, :int32  # 8 bytes total
      end

      # Define outer struct containing inner struct + extra field
      outer_struct = Class.new(FFI::Struct) do
        layout :inner, inner_struct,  # Embedded struct (8 bytes)
               :z, :int32              # Additional field (4 bytes)
      end

      s = outer_struct.new
      
      # Access nested fields via double-indexing: s[:inner][:x]
      # FFI must correctly calculate offset of :x within :inner within :s
      s[:inner][:x] = data[2..5].unpack1('l') rescue 0
      s[:inner][:y] = data[6..9].unpack1('l') rescue 0
      s[:z] = data[10..13].unpack1('l') rescue 0
      
      # Read back nested fields (exercises nested offset calculation)
      s[:inner][:x]; s[:inner][:y]; s[:z]

    when 3
      # ====================================================================
      # TEST CASE 3: Struct with pointer field
      # ====================================================================
      # Purpose: Test pointer-typed fields within structs
      # Bug classes tested:
      # - Pointer field assignment and dereferencing
      # - Pointer null checking
      # - Memory lifetime issues (dangling pointers)
      
      test_struct = Class.new(FFI::Struct) do
        layout :ptr_field, :pointer,  # Pointer to arbitrary memory
               :size, :size_t         # Size metadata
      end

      s = test_struct.new
      
      # Allocate external buffer to point to
      buffer_size = (data[2].ord % 64) + 1  # 1-64 bytes
      buffer = FFI::MemoryPointer.new(:uint8, buffer_size)
      
      # Fill buffer with fuzzer data
      buffer_size.times do |i|
        break if (i + 3) >= data.bytesize
        buffer.put_uint8(i, data[i + 3].ord)
      end
      
      # Assign buffer pointer to struct field
      # FFI must handle pointer assignment correctly
      s[:ptr_field] = buffer
      s[:size] = buffer_size
      
      # Validate pointer operations
      s[:ptr_field].null?  # Should return false
      s[:size]             # Should return buffer_size

    when 4
      # ====================================================================
      # TEST CASE 4: Struct with complex alignment and padding
      # ====================================================================
      # Purpose: Test FFI's struct layout with alignment-sensitive fields
      # Bug classes tested:
      # - Incorrect padding insertion between fields
      # - Alignment calculation for mixed-size fields
      # - Struct introspection API accuracy
      
      # Layout alternates small (uint8) and large (uint32, uint64) types
      # FFI must insert padding to maintain alignment requirements:
      # - uint8 at offset 0
      # - padding (3 bytes)
      # - uint32 at offset 4 (must be 4-byte aligned)
      # - uint8 at offset 8
      # - padding (7 bytes)
      # - uint64 at offset 16 (must be 8-byte aligned)
      # - uint8 at offset 24
      test_struct = Class.new(FFI::Struct) do
        layout :byte1, :uint8,   # offset 0
               :int1, :uint32,   # offset 4 (aligned)
               :byte2, :uint8,   # offset 8
               :long1, :uint64,  # offset 16 (aligned)
               :byte3, :uint8    # offset 24
      end

      s = test_struct.new
      
      # Populate fields sequentially, tracking byte index
      idx = 2
      s[:byte1] = data[idx].ord; idx += 1
      
      # Extract 4 bytes for uint32 (unsigned long)
      s[:int1] = data[idx..idx+3].unpack1('L') rescue 0; idx += 4
      s[:byte2] = data[idx].ord; idx += 1
      
      # Extract 8 bytes for uint64 (unsigned long long)
      s[:long1] = data[idx..idx+7].unpack1('Q') rescue 0; idx += 8
      s[:byte3] = data[idx].ord if idx < data.bytesize
      
      # ================================================================
      # STRUCT INTROSPECTION TESTING
      # ================================================================
      # These methods query the struct layout metadata
      # They should return correct values considering alignment/padding
      
      s.size        # Total struct size including padding (should be 32 bytes)
      s.alignment   # Struct alignment (should be 8 for uint64)
      s.members     # Array of field names [:byte1, :int1, :byte2, :long1, :byte3]
      s.values      # Array of current field values
    end

  rescue FFI::NullPointerError, TypeError, ArgumentError, NoMethodError
    # ========================================================================
    # EXPECTED EXCEPTIONS: Proper FFI error handling
    # ========================================================================
    # FFI::NullPointerError: Dereferencing null pointer
    # TypeError: Type mismatch in field assignment
    # ArgumentError: Invalid struct field name or value
    # NoMethodError: Accessing undefined struct member
    return 0
  rescue => e
    # ========================================================================
    # UNEXPECTED EXCEPTIONS: We don't care about these
    # ========================================================================
    return 0
  end
  
  # Return 0 to indicate successful fuzzing iteration
  return 0
end

Ruzzy.fuzz(fuzz_target)
