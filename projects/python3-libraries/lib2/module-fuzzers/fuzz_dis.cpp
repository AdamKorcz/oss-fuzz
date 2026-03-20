// fuzz_dis.cpp — Fuzzer for CPython's _opcode C extension module via dis.
//
// This fuzzer exercises the following CPython C extension module via
// its Python API, called through the Python C API from C++:
//
//   _opcode (via dis)   — dis.dis() on compiled code objects
//
// All module functions are imported once during init and cached as static
// PyObject* pointers. PyRef (RAII) prevents reference leaks.
// Max input size: 64 KB.

#include "fuzz_helpers.h"

// ---------------------------------------------------------------------------
// Cached module objects, initialized once.
// ---------------------------------------------------------------------------

static PyObject *dis_dis;
static PyObject *stringio_ctor;

static int initialized = 0;

static void init_dis(void) {
  if (initialized) return;

  dis_dis = import_attr("dis", "dis");
  stringio_ctor = import_attr("io", "StringIO");
  assert(!PyErr_Occurred());
  initialized = 1;
}

// ---------------------------------------------------------------------------
// Operations (1 op).
// ---------------------------------------------------------------------------

// OP_DIS: Compile fuzz str to a code object, then call dis.dis(code) with
// output captured to StringIO. Exercises _opcode via the dis module.
static void op_dis(FuzzedDataProvider &fdp) {
  int str_enc = fdp.ConsumeIntegralInRange<int>(0, 3);
  if (fdp.remaining_bytes() == 0) return;
  size_t data_len = fdp.ConsumeIntegralInRange<size_t>(
      1, std::min(fdp.remaining_bytes(), (size_t)10000));
  std::string data = fdp.ConsumeBytesAsString(data_len);
  PyRef pystr(fuzz_bytes_to_str(data, str_enc));
  CHECK(pystr);

  const char *src = "pass";
  if (PyUnicode_GET_LENGTH(pystr) > 0) {
    src = PyUnicode_AsUTF8(pystr);
    if (!src) { PyErr_Clear(); return; }
  }
  PyRef code(Py_CompileString(src, "<f>", Py_file_input));
  if (!code) { PyErr_Clear(); return; }

  // Capture dis output to StringIO.
  PyRef sio = PyObject_CallFunction(stringio_ctor, NULL);
  CHECK(sio);
  PyRef kwargs = PyDict_New();
  CHECK(kwargs);
  PyDict_SetItemString(kwargs, "file", sio);
  PyRef args = PyTuple_Pack(1, (PyObject *)code);
  CHECK(args);
  PyRef r = PyObject_Call(dis_dis, args, kwargs);
  if (PyErr_Occurred()) PyErr_Clear();
}

// ---------------------------------------------------------------------------
// Dispatch.
// ---------------------------------------------------------------------------

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  assert(Py_IsInitialized());
  init_dis();
  if (size < 1 || size > 0x10000) return 0;
  if (PyErr_Occurred()) PyErr_Clear();

  FuzzedDataProvider fdp(data, size);
  op_dis(fdp);

  return 0;
}
