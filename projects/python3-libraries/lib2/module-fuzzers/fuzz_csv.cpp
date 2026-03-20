// fuzz_csv.cpp — Fuzzer for CPython's _csv C extension module.
//
// This fuzzer exercises the following CPython C extension module via
// its Python API, called through the Python C API from C++:
//
//   _csv                — csv.Sniffer.sniff/has_header, csv.writer,
//                          csv.DictWriter with quoting modes
//                          (QUOTE_ALL, QUOTE_NONNUMERIC), tab delimiter
//
// The first byte of fuzz input selects one of 2 operation types. Each
// operation consumes further bytes via FuzzedDataProvider to parameterize
// the call (writer variant, quoting mode, delimiter).
//
// All module functions are imported once during init and cached as static
// PyObject* pointers. PyRef (RAII) prevents reference leaks.
// Max input size: 64 KB.

#include "fuzz_helpers.h"

// ---------------------------------------------------------------------------
// Cached module objects, initialized once.
// ---------------------------------------------------------------------------

static PyObject *csv_Sniffer, *csv_writer, *csv_DictWriter;
static PyObject *csv_QUOTE_ALL, *csv_QUOTE_NONNUMERIC;
static PyObject *stringio_ctor;

static int initialized = 0;

static void init_csv(void) {
  if (initialized) return;

  csv_Sniffer = import_attr("csv", "Sniffer");
  csv_writer = import_attr("csv", "writer");
  csv_DictWriter = import_attr("csv", "DictWriter");
  csv_QUOTE_ALL = import_attr("csv", "QUOTE_ALL");
  csv_QUOTE_NONNUMERIC = import_attr("csv", "QUOTE_NONNUMERIC");
  stringio_ctor = import_attr("io", "StringIO");
  assert(!PyErr_Occurred());
  initialized = 1;
}

// ---------------------------------------------------------------------------
// Operations (2 ops).
// ---------------------------------------------------------------------------

// OP_CSV_SNIFFER: Call csv.Sniffer().sniff() and .has_header() on fuzz str.
// Exercises the _csv C module's dialect detection paths.
static void op_csv_sniffer(FuzzedDataProvider &fdp) {
  int str_enc = fdp.ConsumeIntegralInRange<int>(0, 3);
  if (fdp.remaining_bytes() == 0) return;
  size_t data_len = fdp.ConsumeIntegralInRange<size_t>(
      1, std::min(fdp.remaining_bytes(), (size_t)1024));
  std::string data = fdp.ConsumeBytesAsString(data_len);
  PyRef pystr(fuzz_bytes_to_str(data, str_enc));
  CHECK(pystr);

  PyRef sniffer = PyObject_CallFunction(csv_Sniffer, NULL);
  CHECK(sniffer);

  {
    PyRef r = PyObject_CallMethod(sniffer, "sniff", "O", (PyObject *)pystr);
    if (PyErr_Occurred()) PyErr_Clear();
  }
  {
    PyRef r = PyObject_CallMethod(sniffer, "has_header", "O",
                                  (PyObject *)pystr);
    if (PyErr_Occurred()) PyErr_Clear();
  }
}

// OP_CSV_WRITER: FDP selects variant — basic writerow, writerows, tab-delimited,
// DictWriter, QUOTE_ALL, QUOTE_NONNUMERIC. All write to StringIO.
// Exercises the _csv C module's writer paths.
static void op_csv_writer(FuzzedDataProvider &fdp) {
  int str_enc = fdp.ConsumeIntegralInRange<int>(0, 3);
  enum { WRITEROW, WRITEROWS, TAB_DELIMITED, DICTWRITER, QUOTE_ALL, QUOTE_NONNUMERIC, NUM_TARGETS };
  int target_fn = fdp.ConsumeIntegralInRange<int>(0, NUM_TARGETS - 1);
  if (fdp.remaining_bytes() == 0) return;
  size_t data_len = fdp.ConsumeIntegralInRange<size_t>(
      1, std::min(fdp.remaining_bytes(), (size_t)10000));
  std::string data = fdp.ConsumeBytesAsString(data_len);
  PyRef pystr(fuzz_bytes_to_str(data, str_enc));
  CHECK(pystr);

  PyRef sio = PyObject_CallFunction(stringio_ctor, NULL);
  CHECK(sio);

  // Split string into words for row data.
  PyRef words = PyObject_CallMethod(pystr, "split", NULL);
  if (!words) { PyErr_Clear(); return; }

  // Ensure non-empty.
  if (PyList_Size(words) == 0) {
    PyRef empty = PyUnicode_FromString("");
    PyList_Append(words, empty);
  }

  switch (target_fn) {
    case WRITEROW: {
      // Basic writerow.
      PyRef w = PyObject_CallFunction(csv_writer, "O", (PyObject *)sio);
      CHECK(w);
      PyRef r = PyObject_CallMethod(w, "writerow", "O", (PyObject *)words);
      break;
    }
    case WRITEROWS: {
      // writerows with lines.
      PyRef lines = PyObject_CallMethod(pystr, "splitlines", NULL);
      if (!lines) { PyErr_Clear(); break; }
      PyRef rows = PyList_New(0);
      CHECK(rows);
      Py_ssize_t nlines = PyList_Size(lines);
      for (Py_ssize_t i = 0; i < nlines && i < 20; i++) {
        PyObject *line = PyList_GetItem(lines, i);
        PyRef lwords = PyObject_CallMethod(line, "split", NULL);
        if (!lwords) { PyErr_Clear(); continue; }
        if (PyList_Size(lwords) == 0) {
          PyRef e = PyUnicode_FromString("");
          PyList_Append(lwords, e);
        }
        PyList_Append(rows, lwords);
      }
      PyRef w = PyObject_CallFunction(csv_writer, "O", (PyObject *)sio);
      CHECK(w);
      PyRef r = PyObject_CallMethod(w, "writerows", "O", (PyObject *)rows);
      break;
    }
    case TAB_DELIMITED: {
      // Tab-delimited.
      PyRef kwargs = PyDict_New();
      CHECK(kwargs);
      PyRef delim = PyUnicode_FromString("\t");
      CHECK(delim);
      PyDict_SetItemString(kwargs, "delimiter", delim);
      PyRef args = PyTuple_Pack(1, (PyObject *)sio);
      CHECK(args);
      PyRef w = PyObject_Call(csv_writer, args, kwargs);
      CHECK(w);
      PyRef r = PyObject_CallMethod(w, "writerow", "O", (PyObject *)words);
      break;
    }
    case DICTWRITER: {
      // DictWriter.
      Py_ssize_t nwords = PyList_Size(words);
      Py_ssize_t nfields = nwords < 8 ? nwords : 8;
      if (nfields == 0) nfields = 1;
      PyRef fieldnames = PyList_GetSlice(words, 0, nfields);
      CHECK(fieldnames);
      PyRef kwargs = PyDict_New();
      CHECK(kwargs);
      PyDict_SetItemString(kwargs, "fieldnames", fieldnames);
      PyRef args = PyTuple_Pack(1, (PyObject *)sio);
      CHECK(args);
      PyRef dw = PyObject_Call(csv_DictWriter, args, kwargs);
      CHECK(dw);
      PyRef wh = PyObject_CallMethod(dw, "writeheader", NULL);
      if (PyErr_Occurred()) PyErr_Clear();
      // Build row dict.
      PyRef row = PyDict_New();
      CHECK(row);
      for (Py_ssize_t i = 0; i < nfields; i++) {
        PyObject *fn = PyList_GetItem(fieldnames, i);
        PyDict_SetItem(row, fn, pystr);
      }
      PyRef wr = PyObject_CallMethod(dw, "writerow", "O", (PyObject *)row);
      break;
    }
    case QUOTE_ALL: {
      // QUOTE_ALL.
      PyRef kwargs = PyDict_New();
      CHECK(kwargs);
      PyDict_SetItemString(kwargs, "quoting", csv_QUOTE_ALL);
      PyRef args = PyTuple_Pack(1, (PyObject *)sio);
      CHECK(args);
      PyRef w = PyObject_Call(csv_writer, args, kwargs);
      CHECK(w);
      PyRef r = PyObject_CallMethod(w, "writerow", "O", (PyObject *)words);
      break;
    }
    case QUOTE_NONNUMERIC: {
      // QUOTE_NONNUMERIC.
      PyRef kwargs = PyDict_New();
      CHECK(kwargs);
      PyDict_SetItemString(kwargs, "quoting", csv_QUOTE_NONNUMERIC);
      PyRef args = PyTuple_Pack(1, (PyObject *)sio);
      CHECK(args);
      PyRef w = PyObject_Call(csv_writer, args, kwargs);
      CHECK(w);
      PyRef r = PyObject_CallMethod(w, "writerow", "O", (PyObject *)words);
      break;
    }
  }
  if (PyErr_Occurred()) PyErr_Clear();

  // Read result.
  PyRef val = PyObject_CallMethod(sio, "getvalue", NULL);
  if (PyErr_Occurred()) PyErr_Clear();
}

// ---------------------------------------------------------------------------
// Dispatch.
// ---------------------------------------------------------------------------

enum Op {
  OP_CSV_SNIFFER,
  OP_CSV_WRITER,
  NUM_OPS
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  assert(Py_IsInitialized());
  init_csv();
  if (size < 1 || size > 0x10000) return 0;
  if (PyErr_Occurred()) PyErr_Clear();

  FuzzedDataProvider fdp(data, size);
  switch (fdp.ConsumeIntegralInRange<int>(0, NUM_OPS - 1)) {
    case OP_CSV_SNIFFER:
      op_csv_sniffer(fdp);
      break;
    case OP_CSV_WRITER:
      op_csv_writer(fdp);
      break;
  }

  return 0;
}
