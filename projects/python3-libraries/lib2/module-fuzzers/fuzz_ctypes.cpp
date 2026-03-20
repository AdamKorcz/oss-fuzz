// fuzz_ctypes.cpp — Fuzzer for CPython's _ctypes C extension module.
//
// This fuzzer exercises the following CPython C extension module via
// its Python API, called through the Python C API from C++:
//
//   _ctypes             — c_char/c_int/c_double.from_buffer_copy(),
//                          create_string_buffer, (c_char*N).from_buffer_copy,
//                          Structure.from_buffer_copy
//
// All module functions and class constructors are imported once during init
// and cached as static PyObject* pointers. A Structure subclass is defined
// via PyRun_String at init time.
// PyRef (RAII) prevents reference leaks. Max input size: 64 KB.

#include "fuzz_helpers.h"

// ---------------------------------------------------------------------------
// Cached module objects, initialized once.
// ---------------------------------------------------------------------------

static PyObject *ct_c_char, *ct_c_int, *ct_c_double;
static PyObject *ct_create_string_buffer, *ct_sizeof;
static PyObject *ct_Structure_cls;

static int initialized = 0;

static void init_ctypes(void) {
  if (initialized) return;

  ct_c_char = import_attr("ctypes", "c_char");
  ct_c_int = import_attr("ctypes", "c_int");
  ct_c_double = import_attr("ctypes", "c_double");
  ct_create_string_buffer = import_attr("ctypes", "create_string_buffer");
  ct_sizeof = import_attr("ctypes", "sizeof");

  ct_Structure_cls = run_python_and_get(
      "import ctypes\n"
      "class _S(ctypes.Structure):\n"
      "    _fields_ = [('a', ctypes.c_int), ('b', ctypes.c_double)]\n",
      "_S");
  assert(!PyErr_Occurred());
  initialized = 1;
}

// ---------------------------------------------------------------------------
// Operations (1 op).
// ---------------------------------------------------------------------------

// OP_CTYPES: FDP selects sub-op for different ctypes from_buffer_copy calls.
// Exercises the _ctypes C module's buffer copy and array creation paths.
static void op_ctypes(FuzzedDataProvider &fdp) {
  enum { C_CHAR, C_INT, C_DOUBLE, STRING_BUFFER, CHAR_ARRAY, STRUCTURE, NUM_TARGETS };
  int target_fn = fdp.ConsumeIntegralInRange<int>(0, NUM_TARGETS - 1);
  if (fdp.remaining_bytes() == 0) return;
  size_t data_len = fdp.ConsumeIntegralInRange<size_t>(
      1, std::min(fdp.remaining_bytes(), (size_t)10000));
  std::string data = fdp.ConsumeBytesAsString(data_len);

  switch (target_fn) {
    case C_CHAR: {
      // c_char.from_buffer_copy(1 byte)
      std::string buf = data.substr(0, 1);
      if (buf.empty()) buf.push_back('\0');
      PyRef pydata = PyBytes_FromStringAndSize(buf.data(), buf.size());
      CHECK(pydata);
      PyRef r = PyObject_CallMethod(ct_c_char, "from_buffer_copy", "O",
                                    (PyObject *)pydata);
      break;
    }
    case C_INT: {
      // c_int.from_buffer_copy(4 bytes)
      std::string buf = data.substr(0, 4);
      buf.resize(4, '\0');
      PyRef pydata = PyBytes_FromStringAndSize(buf.data(), buf.size());
      CHECK(pydata);
      PyRef r = PyObject_CallMethod(ct_c_int, "from_buffer_copy", "O",
                                    (PyObject *)pydata);
      break;
    }
    case C_DOUBLE: {
      // c_double.from_buffer_copy(8 bytes)
      std::string buf = data.substr(0, 8);
      buf.resize(8, '\0');
      PyRef pydata = PyBytes_FromStringAndSize(buf.data(), buf.size());
      CHECK(pydata);
      PyRef r = PyObject_CallMethod(ct_c_double, "from_buffer_copy", "O",
                                    (PyObject *)pydata);
      break;
    }
    case STRING_BUFFER: {
      // create_string_buffer(data[:N])
      PyRef pydata = PyBytes_FromStringAndSize(Y(data));
      CHECK(pydata);
      PyRef r = PyObject_CallFunction(ct_create_string_buffer, "O",
                                      (PyObject *)pydata);
      break;
    }
    case CHAR_ARRAY: {
      // (c_char * N).from_buffer_copy(data)
      if (data.empty()) break;
      PyRef n = PyLong_FromLong(data.size());
      CHECK(n);
      PyRef arr_type = PyNumber_Multiply(ct_c_char, n);
      CHECK(arr_type);
      PyRef pydata = PyBytes_FromStringAndSize(Y(data));
      CHECK(pydata);
      PyRef r = PyObject_CallMethod(arr_type, "from_buffer_copy", "O",
                                    (PyObject *)pydata);
      break;
    }
    case STRUCTURE: {
      // Structure.from_buffer_copy(padded data)
      PyRef sz = PyObject_CallFunction(ct_sizeof, "O", ct_Structure_cls);
      CHECK(sz);
      long struct_sz = PyLong_AsLong(sz);
      if (struct_sz <= 0) { PyErr_Clear(); break; }
      std::string buf = data.substr(0, struct_sz);
      buf.resize(struct_sz, '\0');
      PyRef pydata = PyBytes_FromStringAndSize(buf.data(), buf.size());
      CHECK(pydata);
      PyRef r = PyObject_CallMethod(ct_Structure_cls, "from_buffer_copy", "O",
                                    (PyObject *)pydata);
      break;
    }
  }
  if (PyErr_Occurred()) PyErr_Clear();
}

// ---------------------------------------------------------------------------
// Dispatch.
// ---------------------------------------------------------------------------

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  assert(Py_IsInitialized());
  init_ctypes();
  if (size < 1 || size > 0x10000) return 0;
  if (PyErr_Occurred()) PyErr_Clear();

  FuzzedDataProvider fdp(data, size);
  op_ctypes(fdp);

  return 0;
}
