// fuzz_expat.cpp — Fuzzer for CPython's pyexpat C extension module.
//
// This fuzzer exercises the following CPython C extension module via
// its Python API, called through the Python C API from C++:
//
//   pyexpat             — ParserCreate with encodings (utf-8, iso-8859-1,
//                          default) and namespace_separator, Parse/ParseFile,
//                          XML event handlers (StartElement, EndElement,
//                          CharacterData, ProcessingInstruction, Comment,
//                          StartCdataSection, EndCdataSection),
//                          GetInputContext
//
// All module functions are imported once during init and cached as static
// PyObject* pointers. PyRef (RAII) prevents reference leaks.
// Max input size: 64 KB.

#include "fuzz_helpers.h"

// ---------------------------------------------------------------------------
// Cached module objects, initialized once.
// ---------------------------------------------------------------------------

static PyObject *expat_ParserCreate;
static PyObject *bytesio_ctor;

// Handler lambdas (for expat).
static PyObject *noop_handler, *noop_handler_noargs;

static int initialized = 0;

static void init_expat(void) {
  if (initialized) return;

  expat_ParserCreate = import_attr("xml.parsers.expat", "ParserCreate");
  bytesio_ctor = import_attr("io", "BytesIO");

  static const char *kHandlers =
      "_noop = lambda *a: None\n"
      "_noop_noargs = lambda: None\n";
  noop_handler = run_python_and_get(kHandlers, "_noop");
  noop_handler_noargs = run_python_and_get(kHandlers, "_noop_noargs");
  assert(!PyErr_Occurred());
  initialized = 1;
}

// ---------------------------------------------------------------------------
// Operations (1 op).
// ---------------------------------------------------------------------------

// OP_EXPAT: FDP selects encoding and handler setup, then Parse or ParseFile.
// Exercises the pyexpat C module's XML parsing paths.
static void op_expat(FuzzedDataProvider &fdp) {
  static const char *kEncodings[] = {"utf-8", "iso-8859-1", NULL};
  int enc_idx = fdp.ConsumeIntegralInRange<int>(0, 2);
  bool use_ns = fdp.ConsumeBool();
  bool set_handlers = fdp.ConsumeBool();
  bool use_parsefile = fdp.ConsumeBool();
  size_t data_len = fdp.ConsumeIntegralInRange<size_t>(
      1, std::min(fdp.remaining_bytes(), (size_t)4096));
  std::string data = fdp.ConsumeBytesAsString(data_len);

  // Create parser.
  PyRef parser;
  if (use_ns) {
    PyRef kwargs = PyDict_New();
    CHECK(kwargs);
    PyRef ns_sep = PyUnicode_FromString(" ");
    CHECK(ns_sep);
    PyDict_SetItemString(kwargs, "namespace_separator", ns_sep);
    PyRef empty = PyTuple_New(0);
    CHECK(empty);
    parser = PyRef(PyObject_Call(expat_ParserCreate, empty, kwargs));
  } else if (kEncodings[enc_idx]) {
    parser = PyRef(PyObject_CallFunction(expat_ParserCreate, "s",
                                         kEncodings[enc_idx]));
  } else {
    parser = PyRef(PyObject_CallFunction(expat_ParserCreate, NULL));
  }
  CHECK(parser);

  // Set handlers.
  if (set_handlers) {
    PyObject_SetAttrString(parser, "StartElementHandler", noop_handler);
    PyObject_SetAttrString(parser, "EndElementHandler", noop_handler);
    PyObject_SetAttrString(parser, "CharacterDataHandler", noop_handler);
    PyObject_SetAttrString(parser, "ProcessingInstructionHandler",
                           noop_handler);
    PyObject_SetAttrString(parser, "CommentHandler", noop_handler);
    PyObject_SetAttrString(parser, "StartCdataSectionHandler",
                           noop_handler_noargs);
    PyObject_SetAttrString(parser, "EndCdataSectionHandler",
                           noop_handler_noargs);
    if (PyErr_Occurred()) PyErr_Clear();
  }

  PyRef pydata = PyBytes_FromStringAndSize(Y(data));
  CHECK(pydata);

  if (use_parsefile) {
    // ParseFile(BytesIO(data)).
    PyRef bio = PyObject_CallFunction(bytesio_ctor, "O", (PyObject *)pydata);
    CHECK(bio);
    PyRef r = PyObject_CallMethod(parser, "ParseFile", "O", (PyObject *)bio);
  } else {
    // Parse(data, True).
    PyRef r = PyObject_CallMethod(parser, "Parse", "Oi",
                                  (PyObject *)pydata, 1);
  }
  if (PyErr_Occurred()) PyErr_Clear();

  // Optionally GetInputContext.
  if (data.size() % 2 == 0) {
    PyRef ctx = PyObject_CallMethod(parser, "GetInputContext", NULL);
    if (PyErr_Occurred()) PyErr_Clear();
  }
}

// ---------------------------------------------------------------------------
// Dispatch.
// ---------------------------------------------------------------------------

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  assert(Py_IsInitialized());
  init_expat();
  if (size < 1 || size > 0x10000) return 0;
  if (PyErr_Occurred()) PyErr_Clear();

  FuzzedDataProvider fdp(data, size);
  op_expat(fdp);

  return 0;
}
