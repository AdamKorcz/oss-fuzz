// fuzz_array.cpp — Fuzzer for CPython's array C extension module.
//
// This fuzzer exercises the following CPython C extension module via
// its Python API, called through the Python C API from C++:
//
//   array               — array(typecode) with frombytes, tobytes, tolist,
//                          reverse, byteswap, append, extend, pop, count,
//                          index, insert, remove, buffer_info, __sizeof__,
//                          __contains__, __iter__, slice ops, comparison,
//                          concatenation, repetition, fromlist
//
// The first byte of fuzz input selects one of 3 operation types. Each
// operation consumes further bytes via FuzzedDataProvider to parameterize
// the call (typecode, data).
//
// All module functions are imported once during init and cached as static
// PyObject* pointers. PyRef (RAII) prevents reference leaks.
// Max input size: 64 KB.

#include "fuzz_helpers.h"

// ---------------------------------------------------------------------------
// Cached module objects, initialized once.
// ---------------------------------------------------------------------------

static PyObject *array_array;

static int initialized = 0;

static void init_array(void) {
  if (initialized) return;

  array_array = import_attr("array", "array");
  assert(!PyErr_Occurred());
  initialized = 1;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Item sizes for array typecodes.
static int typecode_itemsize(char tc) {
  switch (tc) {
    case 'b': case 'B': return 1;
    case 'H': return 2;
    case 'i': case 'I': case 'l': case 'L': case 'f': return 4;
    case 'd': case 'q': case 'Q': return 8;
    default: return 1;
  }
}

// Create an array with the given typecode and aligned data.
static PyObject *make_array(char tc, const std::string &data) {
  int item_sz = typecode_itemsize(tc);
  size_t aligned_len = (data.size() / item_sz) * item_sz;
  if (aligned_len == 0) aligned_len = item_sz;

  char tc_str[2] = {tc, '\0'};
  PyObject *arr = PyObject_CallFunction(array_array, "s", tc_str);
  if (!arr) return NULL;

  // frombytes with aligned data.
  std::string aligned = data.substr(0, aligned_len);
  if (aligned.size() < (size_t)item_sz) {
    aligned.resize(item_sz, '\0');
  }
  PyRef pydata = PyBytes_FromStringAndSize(aligned.data(), aligned.size());
  if (!pydata) { Py_DECREF(arr); return NULL; }
  PyRef r = PyObject_CallMethod(arr, "frombytes", "O", (PyObject *)pydata);
  if (!r) { PyErr_Clear(); Py_DECREF(arr); return NULL; }
  return arr;
}

// ---------------------------------------------------------------------------
// Operations (3 ops).
// ---------------------------------------------------------------------------

// OP_ARRAY_FROMBYTES: FDP selects typecode, creates array from aligned fuzz
// data, then calls tobytes/tolist/reverse/byteswap. Exercises the array C
// module's core buffer and conversion operations.
static void op_array_frombytes(FuzzedDataProvider &fdp) {
  static const char kTypecodes[] = "bBHiIlLfdqQ";
  char tc = kTypecodes[fdp.ConsumeIntegralInRange<int>(0, 10)];
  size_t data_len = fdp.ConsumeIntegralInRange<size_t>(
      1, std::min(fdp.remaining_bytes(), (size_t)10000));
  std::string data = fdp.ConsumeBytesAsString(data_len);

  PyRef arr(make_array(tc, data));
  CHECK(arr);

  {
    PyRef r = PyObject_CallMethod(arr, "tobytes", NULL);
    if (PyErr_Occurred()) PyErr_Clear();
  }
  {
    PyRef r = PyObject_CallMethod(arr, "tolist", NULL);
    if (PyErr_Occurred()) PyErr_Clear();
  }
  {
    PyRef r = PyObject_CallMethod(arr, "reverse", NULL);
    if (PyErr_Occurred()) PyErr_Clear();
  }
  {
    PyRef r = PyObject_CallMethod(arr, "byteswap", NULL);
    if (PyErr_Occurred()) PyErr_Clear();
  }
}

// OP_ARRAY_METHODS: FDP selects typecode, creates array, then exercises
// append/extend/pop/count/index/insert/remove/buffer_info/__sizeof__/
// __contains__/__iter__/len. Exercises the array C module's element ops.
static void op_array_methods(FuzzedDataProvider &fdp) {
  static const char kTypecodes[] = "bBHiIlLfdqQ";
  char tc = kTypecodes[fdp.ConsumeIntegralInRange<int>(0, 10)];
  size_t data_len = fdp.ConsumeIntegralInRange<size_t>(
      1, std::min(fdp.remaining_bytes(), (size_t)10000));
  std::string data = fdp.ConsumeBytesAsString(data_len);

  PyRef arr(make_array(tc, data));
  CHECK(arr);

  // append(0)
  {
    PyRef zero = PyLong_FromLong(0);
    CHECK(zero);
    PyRef r = PyObject_CallMethod(arr, "append", "O", (PyObject *)zero);
    if (PyErr_Occurred()) PyErr_Clear();
  }

  // extend with a slice.
  {
    PyRef slice = PySequence_GetSlice(arr, 0, 1);
    if (slice) {
      PyRef r = PyObject_CallMethod(arr, "extend", "O", (PyObject *)slice);
      if (PyErr_Occurred()) PyErr_Clear();
    } else {
      PyErr_Clear();
    }
  }

  // pop()
  {
    PyRef r = PyObject_CallMethod(arr, "pop", NULL);
    if (PyErr_Occurred()) PyErr_Clear();
  }

  // count(first_element) and index(first_element)
  {
    PyRef first = PySequence_GetItem(arr, 0);
    if (first) {
      PyRef c = PyObject_CallMethod(arr, "count", "O", (PyObject *)first);
      if (PyErr_Occurred()) PyErr_Clear();
      PyRef idx = PyObject_CallMethod(arr, "index", "O", (PyObject *)first);
      if (PyErr_Occurred()) PyErr_Clear();
    } else {
      PyErr_Clear();
    }
  }

  // insert(0, 42) + remove(42)
  {
    PyRef val = PyLong_FromLong(42);
    CHECK(val);
    PyRef r = PyObject_CallMethod(arr, "insert", "iO", 0, (PyObject *)val);
    if (PyErr_Occurred()) PyErr_Clear();
    PyRef r2 = PyObject_CallMethod(arr, "remove", "O", (PyObject *)val);
    if (PyErr_Occurred()) PyErr_Clear();
  }

  // buffer_info, __sizeof__
  {
    PyRef bi = PyObject_CallMethod(arr, "buffer_info", NULL);
    if (PyErr_Occurred()) PyErr_Clear();
    PyRef sz = PyObject_CallMethod(arr, "__sizeof__", NULL);
    if (PyErr_Occurred()) PyErr_Clear();
  }

  // __contains__, iter, len
  {
    PyRef first = PySequence_GetItem(arr, 0);
    if (first) {
      int r = PySequence_Contains(arr, first);
      (void)r;
      if (PyErr_Occurred()) PyErr_Clear();
    } else {
      PyErr_Clear();
    }
    Py_ssize_t len = PyObject_Length(arr);
    (void)len;
    if (PyErr_Occurred()) PyErr_Clear();
  }
}

// OP_ARRAY_SLICE: FDP selects typecode, creates two arrays, does slice read,
// slice assignment, concatenation, repetition, comparison. Exercises the
// array C module's sequence protocol paths.
static void op_array_slice(FuzzedDataProvider &fdp) {
  static const char kTypecodes[] = "bBHiIlLfdqQ";
  char tc = kTypecodes[fdp.ConsumeIntegralInRange<int>(0, 10)];
  size_t data_len = fdp.ConsumeIntegralInRange<size_t>(
      1, std::min(fdp.remaining_bytes(), (size_t)10000));
  std::string data = fdp.ConsumeBytesAsString(data_len);

  PyRef a1(make_array(tc, data));
  CHECK(a1);
  PyRef a2(make_array(tc, data));
  CHECK(a2);

  // Slice read a1[0:N].
  {
    Py_ssize_t len = PyObject_Length(a1);
    Py_ssize_t n = len < 4 ? len : 4;
    PyRef sl = PySequence_GetSlice(a1, 0, n);
    if (PyErr_Occurred()) PyErr_Clear();
  }

  // Slice assignment a1[::2] = array of zeros.
  {
    Py_ssize_t len = PyObject_Length(a1);
    if (len > 0) {
      // Count elements in a1[::2].
      Py_ssize_t slice_len = (len + 1) / 2;
      // Build array of zeros with same typecode.
      char tc_str[2] = {tc, '\0'};
      PyRef zeros_arr = PyObject_CallFunction(array_array, "s", tc_str);
      if (zeros_arr) {
        std::string zero_data(slice_len * typecode_itemsize(tc), '\0');
        PyRef pydata = PyBytes_FromStringAndSize(zero_data.data(),
                                                 zero_data.size());
        if (pydata) {
          PyRef fb = PyObject_CallMethod(zeros_arr, "frombytes", "O",
                                         (PyObject *)pydata);
          if (fb) {
            PyRef step = PyLong_FromLong(2);
            PyRef sl = PySlice_New(NULL, NULL, step);
            if (sl) {
              int r = PyObject_SetItem(a1, sl, zeros_arr);
              (void)r;
            }
          }
        }
      }
      if (PyErr_Occurred()) PyErr_Clear();
    }
  }

  // Concatenation a1 + a2.
  {
    PyRef r = PySequence_Concat(a1, a2);
    if (PyErr_Occurred()) PyErr_Clear();
  }

  // Repetition a1 * min(len, 3).
  {
    Py_ssize_t len = PyObject_Length(a1);
    int rep = len < 3 ? (int)len : 3;
    PyRef r = PySequence_Repeat(a1, rep);
    if (PyErr_Occurred()) PyErr_Clear();
  }

  // Comparison a1 == a2.
  {
    PyRef r = PyObject_RichCompare(a1, a2, Py_EQ);
    if (PyErr_Occurred()) PyErr_Clear();
  }
}

// ---------------------------------------------------------------------------
// Dispatch.
// ---------------------------------------------------------------------------

enum Op {
  OP_ARRAY_FROMBYTES,
  OP_ARRAY_METHODS,
  OP_ARRAY_SLICE,
  NUM_OPS
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  assert(Py_IsInitialized());
  init_array();
  if (size < 1 || size > 0x10000) return 0;
  if (PyErr_Occurred()) PyErr_Clear();

  FuzzedDataProvider fdp(data, size);
  switch (fdp.ConsumeIntegralInRange<int>(0, NUM_OPS - 1)) {
    case OP_ARRAY_FROMBYTES:
      op_array_frombytes(fdp);
      break;
    case OP_ARRAY_METHODS:
      op_array_methods(fdp);
      break;
    case OP_ARRAY_SLICE:
      op_array_slice(fdp);
      break;
  }

  return 0;
}
