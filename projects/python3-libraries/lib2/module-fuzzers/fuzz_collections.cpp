// fuzz_collections.cpp — Fuzzer for CPython's collections C extension module.
//
// This fuzzer exercises the following CPython C extension module via
// its Python API, called through the Python C API from C++:
//
//   collections          — _count_elements (Counter internals C path)
//
// All module functions are imported once during init and cached as static
// PyObject* pointers. PyRef (RAII) prevents reference leaks.
// Max input size: 64 KB.

#include "fuzz_helpers.h"

// ---------------------------------------------------------------------------
// Cached module objects, initialized once.
// ---------------------------------------------------------------------------

static PyObject *collections_count_elements;

static int initialized = 0;

static void init_collections(void) {
  if (initialized) return;

  collections_count_elements = import_attr("collections", "_count_elements");
  assert(!PyErr_Occurred());
  initialized = 1;
}

// ---------------------------------------------------------------------------
// Operations (1 op).
// ---------------------------------------------------------------------------

// OP_COLLECTIONS_COUNT: Build a dict and call collections._count_elements()
// with a fuzz-generated string. Exercises the Counter internals C path.
static void op_collections_count(FuzzedDataProvider &fdp) {
  int str_enc = fdp.ConsumeIntegralInRange<int>(0, 3);
  if (fdp.remaining_bytes() == 0) return;
  size_t data_len = fdp.ConsumeIntegralInRange<size_t>(
      1, std::min(fdp.remaining_bytes(), (size_t)10000));
  std::string data = fdp.ConsumeBytesAsString(data_len);
  PyRef pystr(fuzz_bytes_to_str(data, str_enc));
  CHECK(pystr);

  PyRef d = PyDict_New();
  CHECK(d);
  PyRef r = PyObject_CallFunction(collections_count_elements, "OO",
                                  (PyObject *)d, (PyObject *)pystr);
  if (PyErr_Occurred()) PyErr_Clear();
}

// ---------------------------------------------------------------------------
// Dispatch.
// ---------------------------------------------------------------------------

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  assert(Py_IsInitialized());
  init_collections();
  if (size < 1 || size > 0x10000) return 0;
  if (PyErr_Occurred()) PyErr_Clear();

  FuzzedDataProvider fdp(data, size);
  op_collections_count(fdp);

  return 0;
}
