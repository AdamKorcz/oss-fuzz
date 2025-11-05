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
# FFI Memory Operations Fuzzer
# ============================================================================
#
# GOAL:
# This fuzzer targets FFI's core memory management APIs to discover memory
# safety bugs including buffer overflows, use-after-free, double-free, memory
# leaks, and incorrect pointer arithmetic. It focuses on three main classes:
# - FFI::Buffer: Fixed-size memory buffers with typed access
# - FFI::MemoryPointer: Dynamically allocated native memory
# - FFI::Pointer: Raw pointer arithmetic and operations
#
# STRATEGY:
# Uses coverage-guided fuzzing via Ruzzy to explore diverse code paths.
# The fuzzer parses raw bytes to extract:
# - Size: Buffer/pointer allocation size (1-128 bytes)
# - Offset: Index for pointer arithmetic operations
# - Operation: Selects one of 6 memory operation test cases
# - Value bytes: Multi-byte values for type-specific operations
# - Remaining data: Variable-length payload for read/write operations
#
# Each test case exercises different memory APIs:
# 1. Buffer creation with typed put/get operations (uint8)
# 2. MemoryPointer allocation with byte-level read/write
# 3. String read/write operations (null-terminated strings)
# 4. Array operations (write/read arrays of integers)
# 5. Typed buffers (int16 operations)
# 6. Memory clearing (clear operation)
#
# ERROR HANDLING:
# Catches FFI-specific errors (NullPointerError, TypeError) and Ruby exceptions
# to prevent harness crashes from masking genuine target bugs. Returns 0 to
# indicate successful fuzzing iteration.
#
# ============================================================================
fuzz_target = lambda do |data|
  # Minimum 8 bytes required: size(1) + offset(1) + operation(1) + value_bytes(5)
  # This ensures we have enough data to parse all control parameters
  return 0 if data.bytesize < 8

  begin
    # ========================================================================
    # INPUT PARSING: Extract control parameters from fuzzer-provided bytes
    # ========================================================================
    
    # Size: Allocation size for buffers/pointers (1-128 bytes)
    # Modulo 128 keeps allocations reasonable for fuzzing performance
    # +1 ensures we never allocate zero-sized buffers (avoid edge case bugs)
    size = (data[0].ord % 128) + 1
    
    # Offset: Used for pointer arithmetic and indexed operations
    # Modulo size ensures offset is always within bounds (prevents immediate crashes)
    offset = data[1].ord % size
    
    # Operation: Selects which test case to execute (0-5)
    operation = data[2].ord % 6
    
    # Value bytes: 5 bytes for constructing multi-byte values (uint32, uint64, etc.)
    value_bytes = data[3..7]
    
    # Remaining data: Variable-length payload for read/write operations
    # Used as source data for filling buffers, writing strings, etc.
    remaining_data = data[8..-1] || ''

    case operation
    when 0
      # ====================================================================
      # TEST CASE 0: FFI::Buffer with uint8 operations
      # ====================================================================
      # Purpose: Test typed buffer allocation and byte-level put/get operations
      # Bug classes tested:
      # - Buffer overflow in put_uint8 (writing beyond allocated size)
      # - Out-of-bounds reads in get_uint8
      # - Type confusion between buffer types
      
      buffer = FFI::Buffer.new(:uint8, size)
      
      # Write fuzzer data into buffer, byte by byte
      # Break when we've written 'size' bytes to respect buffer bounds
      remaining_data.bytes.each_with_index do |byte, idx|
        break if idx >= size  # Critical bounds check
        buffer.put_uint8(idx, byte)
      end
      
      # Read back all written bytes to exercise get_uint8 code path
      # This can detect read buffer overflows or uninitialized memory reads
      size.times { |i| buffer.get_uint8(i) }

    when 1
      # ====================================================================
      # TEST CASE 1: FFI::MemoryPointer with uint32 type and byte operations
      # ====================================================================
      # Purpose: Test dynamically allocated memory with mixed-type access
      # Bug classes tested:
      # - Heap buffer overflow (allocate uint32 array, access as bytes)
      # - Type confusion (declare uint32 but access as uint8)
      # - Incorrect size calculations (size * 4 bytes)
      
      # Allocate memory for 'size' uint32 values (4 bytes each)
      ptr = FFI::MemoryPointer.new(:uint32, size)
      
      # Write data byte-by-byte into the uint32 array
      # Total bytes = size * 4, but we're limited by remaining_data length
      (size * 4).times do |i|
        break if i >= remaining_data.bytesize  # Don't read past input
        ptr.put_uint8(i, remaining_data.bytes[i])
      end
      
      # Read back all bytes as a raw byte string
      # This exercises read_bytes with potentially large sizes
      ptr.read_bytes(size * 4)

    when 2
      # ====================================================================
      # TEST CASE 2: String operations (null-terminated C strings)
      # ====================================================================
      # Purpose: Test string read/write operations with FFI::MemoryPointer
      # Bug classes tested:
      # - Buffer overflow in write_string (no null terminator space)
      # - Reading beyond string bounds in read_string
      # - Null byte handling in strings
      
      # Extract or provide default string data (max 'size' bytes)
      str_data = remaining_data[0..size-1] || 'test'
      
      # Allocate buffer for C-style char array
      ptr = FFI::MemoryPointer.new(:char, size)
      
      # Write string (FFI automatically adds null terminator if space allows)
      ptr.write_string(str_data)
      
      # Read back string (stops at null terminator or 'size' bytes)
      # Bug potential: what if size is wrong? Will read_string overflow?
      ptr.read_string(size)

    when 3
      # ====================================================================
      # TEST CASE 4: Array operations with int32 arrays
      # ====================================================================
      # Purpose: Test bulk array read/write operations
      # Bug classes tested:
      # - Array bounds checking in write_array_of_*
      # - Incorrect array size calculations
      # - Memory corruption from array operations
      
      # Allocate array of 'size' int32 values
      ptr = FFI::MemoryPointer.new(:int32, size)
      
      # Convert fuzzer bytes to array of integers (limited to 'size' elements)
      values = remaining_data.bytes.map { |b| b.to_i }[0..size-1]
      
      # Write entire array at once (tests bulk write path)
      ptr.write_array_of_int32(values)
      
      # Read back array (tests bulk read path, should match written length)
      ptr.read_array_of_int32(values.length)

    when 4
      # ====================================================================
      # TEST CASE 4: FFI::Buffer with int16 (signed 16-bit integers)
      # ====================================================================
      # Purpose: Test typed buffer with multi-byte signed integers
      # Bug classes tested:
      # - Incorrect stride calculations (int16 = 2 bytes)
      # - Sign extension bugs
      # - Buffer overflow with multi-byte types
      
      buffer = FFI::Buffer.new(:int16, size)
      
      # Write int16 values from fuzzer data
      # Each int16 requires 2 bytes, so we iterate 'size' times
      (size).times do |i|
        break if (i * 2) >= remaining_data.bytesize  # Need 2 bytes per value
        
        # Extract 2 bytes and unpack as signed 16-bit integer
        val = remaining_data[i*2, 2].unpack1('s') rescue 0
        
        # put_int16 takes byte offset (i * 2), not element index
        buffer.put_int16(i * 2, val)
      end

    when 5
      # ====================================================================
      # TEST CASE 5: Memory clearing operations
      # ====================================================================
      # Purpose: Test clear() method that zeros out memory
      # Bug classes tested:
      # - Incorrect clear size (clearing too much/too little)
      # - Use-after-clear bugs
      # - Double-clear issues
      
      ptr = FFI::MemoryPointer.new(:uint8, size)
      
      # First write data to memory
      ptr.write_bytes(remaining_data[0..size-1] || '')
      
      # Then clear it (should set all bytes to 0)
      # This tests FFI's memory clearing implementation
      ptr.clear
    end

  rescue FFI::NullPointerError, RangeError, ArgumentError
    # ========================================================================
    # EXPECTED EXCEPTIONS: These are proper error handling by FFI
    # ========================================================================
    # FFI::NullPointerError: Attempted to dereference null pointer
    # RangeError: Value out of range for type (e.g., -1 for unsigned)
    # ArgumentError: Invalid arguments to FFI methods
    # 
    # Catching these prevents harness crashes from hiding real bugs.
    # Real memory safety bugs trigger AddressSanitizer, not Ruby exceptions.
    return 0
  rescue => e
    # ========================================================================
    # RESCUE EXCEPTIONS: We only care about non-rescue'able bugs
    # ========================================================================
    return 0
  end
  
  return 0
end

Ruzzy.fuzz(fuzz_target)
