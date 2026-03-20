// fuzz_datetime.cpp — Fuzzer for CPython's datetime C extension module.
//
// This fuzzer exercises the following CPython C extension module via
// its Python API, called through the Python C API from C++:
//
//   datetime             — date/time/datetime.fromisoformat(), strptime(),
//                          strftime(), format()
//
// The first byte of fuzz input selects one of 2 operation types. Each
// operation consumes further bytes via FuzzedDataProvider to parameterize
// the call (format selection, character range).
//
// All module functions and class constructors are imported once during init
// and cached as static PyObject* pointers. PyRef (RAII) prevents reference
// leaks. Max input size: 64 KB.

#include "fuzz_helpers.h"

// ---------------------------------------------------------------------------
// Cached module objects, initialized once.
// ---------------------------------------------------------------------------

static PyObject *dt_date, *dt_time, *dt_datetime;
static PyObject *struct_unpack;

static int initialized = 0;

static void init_datetime(void) {
  if (initialized) return;

  dt_date = import_attr("datetime", "date");
  dt_time = import_attr("datetime", "time");
  dt_datetime = import_attr("datetime", "datetime");
  struct_unpack = import_attr("struct", "unpack");
  assert(!PyErr_Occurred());
  initialized = 1;
}

// ---------------------------------------------------------------------------
// Operations (2 ops).
// ---------------------------------------------------------------------------

// OP_DATETIME_PARSE: FDP selects variant — date/time/datetime.fromisoformat()
// or datetime.strptime() with a fuzz-chosen format string. Exercises the
// datetime C module's parsing paths.
static void op_datetime_parse(FuzzedDataProvider &fdp) {
  int str_enc = fdp.ConsumeIntegralInRange<int>(0, 3);
  enum { DATE_ISO, TIME_ISO, DATETIME_ISO, STRPTIME_YMD_HMS, STRPTIME_YMD_HM, NUM_TARGETS };
  int target_fn = fdp.ConsumeIntegralInRange<int>(0, NUM_TARGETS - 1);
  size_t data_len = fdp.ConsumeIntegralInRange<size_t>(
      1, std::min(fdp.remaining_bytes(), (size_t)10000));
  std::string data = fdp.ConsumeBytesAsString(data_len);
  PyRef pystr(fuzz_bytes_to_str(data, str_enc));
  CHECK(pystr);

  switch (target_fn) {
    case DATE_ISO: {
      PyRef r = PyObject_CallMethod(dt_date, "fromisoformat", "O",
                                    (PyObject *)pystr);
      break;
    }
    case TIME_ISO: {
      PyRef r = PyObject_CallMethod(dt_time, "fromisoformat", "O",
                                    (PyObject *)pystr);
      break;
    }
    case DATETIME_ISO: {
      PyRef r = PyObject_CallMethod(dt_datetime, "fromisoformat", "O",
                                    (PyObject *)pystr);
      break;
    }
    case STRPTIME_YMD_HMS: {
      PyRef fmt = PyUnicode_FromString("%Y-%m-%d %H:%M:%S");
      CHECK(fmt);
      PyRef r = PyObject_CallMethod(dt_datetime, "strptime", "OO",
                                    (PyObject *)pystr, (PyObject *)fmt);
      break;
    }
    case STRPTIME_YMD_HM: {
      PyRef fmt = PyUnicode_FromString("%Y/%m/%dT%H:%M");
      CHECK(fmt);
      PyRef r = PyObject_CallMethod(dt_datetime, "strptime", "OO",
                                    (PyObject *)pystr, (PyObject *)fmt);
      break;
    }
  }
  if (PyErr_Occurred()) PyErr_Clear();
}

// OP_DATETIME_FORMAT: Unpack 6 shorts from first 12 bytes to build a valid
// datetime, then call strftime() with the remaining fuzz data as the format
// string. Exercises datetime formatting code paths.
static void op_datetime_format(FuzzedDataProvider &fdp) {
  // Need at least 12 bytes for the datetime fields.
  std::string header = fdp.ConsumeBytesAsString(12);
  if (header.size() < 12) return;

  int str_enc = fdp.ConsumeIntegralInRange<int>(0, 3);
  size_t fmt_len = fdp.ConsumeIntegralInRange<size_t>(
      1, std::min(fdp.remaining_bytes(), (size_t)10000));
  std::string fmt_data = fdp.ConsumeBytesAsString(fmt_len);
  PyRef fmt_str(fuzz_bytes_to_str(fmt_data, str_enc));
  CHECK(fmt_str);

  // Unpack 6 unsigned shorts via struct.unpack.
  PyRef hdr_bytes = PyBytes_FromStringAndSize(header.data(), 12);
  CHECK(hdr_bytes);
  PyRef vals = PyObject_CallFunction(struct_unpack, "sO", "6H",
                                     (PyObject *)hdr_bytes);
  CHECK(vals);

  // Extract fields and clamp to valid ranges.
  long v[6];
  for (int i = 0; i < 6; i++) {
    PyObject *item = PyTuple_GetItem(vals, i);  // borrowed
    if (!item) { PyErr_Clear(); return; }
    v[i] = PyLong_AsLong(item);
  }
  long year = (v[0] % 9999) + 1;
  long month = (v[1] % 12) + 1;
  long day = (v[2] % 28) + 1;
  long hour = v[3] % 24;
  long minute = v[4] % 60;
  long second = v[5] % 60;

  PyRef dt = PyObject_CallFunction(dt_datetime, "llllll",
                                   year, month, day, hour, minute, second);
  CHECK(dt);

  // strftime on datetime.
  {
    PyRef r = PyObject_CallMethod(dt, "strftime", "O", (PyObject *)fmt_str);
    if (PyErr_Occurred()) PyErr_Clear();
  }

  // strftime on date.
  {
    PyRef date_obj = PyObject_CallMethod(dt, "date", NULL);
    if (date_obj) {
      PyRef r = PyObject_CallMethod(date_obj, "strftime", "O",
                                    (PyObject *)fmt_str);
      if (PyErr_Occurred()) PyErr_Clear();
    } else {
      PyErr_Clear();
    }
  }

  // strftime on time.
  {
    PyRef time_obj = PyObject_CallMethod(dt, "time", NULL);
    if (time_obj) {
      PyRef r = PyObject_CallMethod(time_obj, "strftime", "O",
                                    (PyObject *)fmt_str);
      if (PyErr_Occurred()) PyErr_Clear();
    } else {
      PyErr_Clear();
    }
  }

  // format(date, str[:16]).
  {
    PyRef date_obj = PyObject_CallMethod(dt, "date", NULL);
    if (date_obj) {
      // Cap format spec to 16 chars.
      Py_ssize_t flen = PyUnicode_GET_LENGTH(fmt_str);
      PyRef short_fmt = PyUnicode_Substring(fmt_str, 0,
                                            flen < 16 ? flen : 16);
      if (short_fmt) {
        PyRef r = PyObject_Format(date_obj, short_fmt);
        if (PyErr_Occurred()) PyErr_Clear();
      } else {
        PyErr_Clear();
      }
    } else {
      PyErr_Clear();
    }
  }
}

// ---------------------------------------------------------------------------
// Dispatch.
// ---------------------------------------------------------------------------

enum Op {
  OP_DATETIME_PARSE,
  OP_DATETIME_FORMAT,
  NUM_OPS
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  assert(Py_IsInitialized());
  init_datetime();
  if (size < 1 || size > 0x10000) return 0;
  if (PyErr_Occurred()) PyErr_Clear();

  FuzzedDataProvider fdp(data, size);
  switch (fdp.ConsumeIntegralInRange<int>(0, NUM_OPS - 1)) {
    case OP_DATETIME_PARSE:
      op_datetime_parse(fdp);
      break;
    case OP_DATETIME_FORMAT:
      op_datetime_format(fdp);
      break;
  }

  return 0;
}
