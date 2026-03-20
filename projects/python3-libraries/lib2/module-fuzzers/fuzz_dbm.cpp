// fuzz_dbm.cpp — Fuzzer for CPython's _dbm C extension module.
//
// This fuzzer exercises the following CPython C extension module via
// its Python API, called through the Python C API from C++:
//
//   _dbm                — dbm.open, write, read, keys, delete, iteration
//
// Exercises the _dbm C extension module's storage operations wrapping
// the third-party gdbm/ndbm library.
//
// All module functions are imported once during init and cached as static
// PyObject* pointers. PyRef (RAII) prevents reference leaks.
// Max input size: 64 KB.

#include <unistd.h>

#include "fuzz_helpers.h"

// ---------------------------------------------------------------------------
// Cached module objects, initialized once.
// ---------------------------------------------------------------------------

static PyObject *dbm_open;
static PyObject *glob_glob;

static int initialized = 0;

static void init_dbm(void) {
  if (initialized) return;

  dbm_open = import_attr("dbm", "open");
  glob_glob = import_attr("glob", "glob");
  assert(!PyErr_Occurred());
  initialized = 1;
}

// ---------------------------------------------------------------------------
// Operations (1 op)
// ---------------------------------------------------------------------------

// OP_DBM: Open an in-memory dbm, write N key-value pairs, read back, iterate.
// Exercises the _dbm C extension module's storage operations.
static void op_dbm(FuzzedDataProvider &fdp) {
  if (fdp.remaining_bytes() == 0) return;
  size_t data_len = fdp.ConsumeIntegralInRange<size_t>(
      1, std::min(fdp.remaining_bytes(), (size_t)10000));
  std::string data = fdp.ConsumeBytesAsString(data_len);

  static const char *dbpath = "/tmp/_fuzz_dbm";

  PyRef db = PyObject_CallFunction(dbm_open, "ss", dbpath, "n");
  CHECK(db);

  // Write key-value pairs from fuzz data.
  size_t offset = 0;
  for (int count = 0; count < 16 && offset < data.size(); count++) {
    size_t key_len = fdp.ConsumeIntegralInRange<size_t>(1,
        std::min((size_t)256, data.size() - offset));
    if (offset + key_len > data.size()) break;
    PyRef key = PyBytes_FromStringAndSize(data.data() + offset, key_len);
    if (!key) { PyErr_Clear(); break; }
    offset += key_len;
    size_t val_len = fdp.ConsumeIntegralInRange<size_t>(0,
        std::min((size_t)256, data.size() - offset));
    if (offset + val_len > data.size()) val_len = data.size() - offset;
    PyRef val = PyBytes_FromStringAndSize(data.data() + offset, val_len);
    if (!val) { PyErr_Clear(); break; }
    offset += val_len;
    int r = PyObject_SetItem(db, key, val);
    (void)r;
    if (PyErr_Occurred()) PyErr_Clear();
  }

  // Read keys.
  {
    PyRef keys = PyObject_CallMethod(db, "keys", NULL);
    if (keys) {
      PyRef it = PyObject_GetIter(keys);
      if (it) {
        PyObject *k;
        while ((k = PyIter_Next(it)) != NULL) {
          PyRef val = PyObject_GetItem(db, k);
          Py_DECREF(k);
          if (PyErr_Occurred()) PyErr_Clear();
        }
      }
    }
    if (PyErr_Occurred()) PyErr_Clear();
  }

  // Check membership.
  {
    size_t tk_len = fdp.ConsumeIntegralInRange<size_t>(1,
        std::min((size_t)64, data.size() > 0 ? data.size() : (size_t)1));
    PyRef test_key = PyBytes_FromStringAndSize(data.data(),
        std::min(tk_len, data.size()));
    if (test_key) {
      int r = PySequence_Contains(db, test_key);
      (void)r;
      if (PyErr_Occurred()) PyErr_Clear();
    }
  }

  // Close.
  {
    PyRef r = PyObject_CallMethod(db, "close", NULL);
    if (PyErr_Occurred()) PyErr_Clear();
  }

  // Clean up dbm files (may have .db, .dir, .bak, .dat extensions).
  {
    PyRef files = PyObject_CallFunction(glob_glob, "s", "/tmp/_fuzz_dbm*");
    if (files) {
      Py_ssize_t n = PyList_Size(files);
      for (Py_ssize_t i = 0; i < n; i++) {
        PyObject *item = PyList_GetItem(files, i);  // borrowed
        if (!item) continue;
        const char *path = PyUnicode_AsUTF8(item);
        if (path) unlink(path);
      }
    }
    if (PyErr_Occurred()) PyErr_Clear();
  }
}

// ---------------------------------------------------------------------------
// Dispatch.
// ---------------------------------------------------------------------------

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  assert(Py_IsInitialized());
  init_dbm();
  if (size < 1 || size > 0x10000) return 0;
  if (PyErr_Occurred()) PyErr_Clear();

  FuzzedDataProvider fdp(data, size);
  op_dbm(fdp);

  return 0;
}
