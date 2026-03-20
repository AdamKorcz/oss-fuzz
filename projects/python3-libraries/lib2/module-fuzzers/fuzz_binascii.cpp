// fuzz_binascii.cpp — Fuzzer for CPython's binascii C extension module.
//
// This fuzzer exercises the following CPython C extension module via
// its Python API, called through the Python C API from C++:
//
//   binascii           — 6 decoders: a2b_base64 (with strict_mode), a2b_hex,
//                         a2b_uu, a2b_qp, a2b_ascii85, a2b_base85
//                         6 encoders: b2a_base64 (with newline), b2a_hex,
//                         b2a_uu (clamped to 45 bytes), b2a_qp,
//                         b2a_ascii85 (with foldspaces/wrapcol), b2a_base85
//                         Checksums: crc32, crc_hqx
//                         Round-trip: hexlify -> unhexlify
//
// The first byte of fuzz input selects one of 4 operation types. Each
// operation consumes further bytes via FuzzedDataProvider to parameterize
// the call (encoder/decoder selection, boolean flags).
//
// All module functions are imported once during init and cached as static
// PyObject* pointers. PyRef (RAII) prevents reference leaks.
// Max input size: 1 MB.

#include "fuzz_helpers.h"

// ---------------------------------------------------------------------------
// Cached module objects, initialized once.
// ---------------------------------------------------------------------------

static PyObject *ba_a2b_base64, *ba_a2b_hex, *ba_a2b_uu, *ba_a2b_qp;
static PyObject *ba_a2b_ascii85, *ba_a2b_base85;
static PyObject *ba_b2a_base64, *ba_b2a_hex, *ba_b2a_uu, *ba_b2a_qp;
static PyObject *ba_b2a_ascii85, *ba_b2a_base85;
static PyObject *ba_crc32, *ba_crc_hqx, *ba_hexlify, *ba_unhexlify;

static int initialized = 0;

static void init_binascii(void) {
  if (initialized) return;

  ba_a2b_base64 = import_attr("binascii", "a2b_base64");
  ba_a2b_hex = import_attr("binascii", "a2b_hex");
  ba_a2b_uu = import_attr("binascii", "a2b_uu");
  ba_a2b_qp = import_attr("binascii", "a2b_qp");
  ba_a2b_ascii85 = import_attr("binascii", "a2b_ascii85");
  ba_a2b_base85 = import_attr("binascii", "a2b_base85");
  ba_b2a_base64 = import_attr("binascii", "b2a_base64");
  ba_b2a_hex = import_attr("binascii", "b2a_hex");
  ba_b2a_uu = import_attr("binascii", "b2a_uu");
  ba_b2a_qp = import_attr("binascii", "b2a_qp");
  ba_b2a_ascii85 = import_attr("binascii", "b2a_ascii85");
  ba_b2a_base85 = import_attr("binascii", "b2a_base85");
  ba_crc32 = import_attr("binascii", "crc32");
  ba_crc_hqx = import_attr("binascii", "crc_hqx");
  ba_hexlify = import_attr("binascii", "hexlify");
  ba_unhexlify = import_attr("binascii", "unhexlify");

  assert(!PyErr_Occurred());
  initialized = 1;
}

// ---------------------------------------------------------------------------
// Operations (4 ops)
// ---------------------------------------------------------------------------

// OP_BINASCII_DECODE: Call one of 6 binary-to-binary decoders from the
// binascii C module: a2b_base64 (with optional strict_mode=True), a2b_hex,
// a2b_uu, a2b_qp, a2b_ascii85, a2b_base85. Fuzz selects which decoder.
static void op_binascii_decode(FuzzedDataProvider &fdp) {
  int which = fdp.ConsumeIntegralInRange<int>(0, 5);
  bool strict = fdp.ConsumeBool();
  std::string data = fdp.ConsumeRemainingBytesAsString();
  PyRef pydata = PyBytes_FromStringAndSize(Y(data));
  CHECK(pydata);

  PyObject *funcs[] = {
    ba_a2b_base64, ba_a2b_hex, ba_a2b_uu,
    ba_a2b_qp, ba_a2b_ascii85, ba_a2b_base85,
  };

  if (which == 0 && strict) {
    PyRef kwargs = PyDict_New();
    CHECK(kwargs);
    PyDict_SetItemString(kwargs, "strict_mode", Py_True);
    PyRef args = PyTuple_Pack(1, (PyObject *)pydata);
    CHECK(args);
    PyRef r = PyObject_Call(ba_a2b_base64, args, kwargs);
  } else {
    PyRef r = PyObject_CallFunction(funcs[which], "O",
                                    (PyObject *)pydata);
  }
  if (PyErr_Occurred()) PyErr_Clear();
}

// OP_BINASCII_ENCODE: Call one of 6 binary-to-text encoders from the
// binascii C module: b2a_base64 (with optional newline kwarg), b2a_hex,
// b2a_uu (input clamped to 45 bytes), b2a_qp, b2a_ascii85 (with optional
// foldspaces and wrapcol=72), b2a_base85. Fuzz selects which encoder.
static void op_binascii_encode(FuzzedDataProvider &fdp) {
  int which = fdp.ConsumeIntegralInRange<int>(0, 5);
  if (fdp.remaining_bytes() == 0) return;
  size_t data_len = fdp.ConsumeIntegralInRange<size_t>(
      1, std::min(fdp.remaining_bytes(), (size_t)10000));
  std::string data = fdp.ConsumeBytesAsString(data_len);

  // b2a_uu requires <= 45 bytes.
  if (which == 2 && data.size() > 45) data.resize(45);

  PyRef pydata = PyBytes_FromStringAndSize(Y(data));
  CHECK(pydata);

  PyObject *funcs[] = {
    ba_b2a_base64, ba_b2a_hex, ba_b2a_uu,
    ba_b2a_qp, ba_b2a_ascii85, ba_b2a_base85,
  };

  if (which == 0) {
    // b2a_base64 with optional newline kwarg.
    bool newline = fdp.ConsumeBool();
    PyRef kwargs = PyDict_New();
    CHECK(kwargs);
    PyDict_SetItemString(kwargs, "newline", newline ? Py_True : Py_False);
    PyRef args = PyTuple_Pack(1, (PyObject *)pydata);
    CHECK(args);
    PyRef r = PyObject_Call(ba_b2a_base64, args, kwargs);
  } else if (which == 4) {
    // b2a_ascii85 with optional foldspaces/wrapcol.
    bool foldspaces = fdp.ConsumeBool();
    PyRef kwargs = PyDict_New();
    CHECK(kwargs);
    if (foldspaces)
      PyDict_SetItemString(kwargs, "foldspaces", Py_True);
    PyRef wrapcol = PyLong_FromLong(72);
    CHECK(wrapcol);
    PyDict_SetItemString(kwargs, "wrapcol", wrapcol);
    PyRef args = PyTuple_Pack(1, (PyObject *)pydata);
    CHECK(args);
    PyRef r = PyObject_Call(ba_b2a_ascii85, args, kwargs);
  } else {
    PyRef r = PyObject_CallFunction(funcs[which], "O",
                                    (PyObject *)pydata);
  }
  if (PyErr_Occurred()) PyErr_Clear();
}

// OP_BINASCII_CHECKSUM: Call either binascii.crc32(data) or
// binascii.crc_hqx(data, 0), fuzz-chosen.
static void op_binascii_checksum(FuzzedDataProvider &fdp) {
  bool use_crc32 = fdp.ConsumeBool();
  std::string data = fdp.ConsumeRemainingBytesAsString();
  PyRef pydata = PyBytes_FromStringAndSize(Y(data));
  CHECK(pydata);

  if (use_crc32) {
    PyRef r = PyObject_CallFunction(ba_crc32, "O", (PyObject *)pydata);
  } else {
    PyRef r = PyObject_CallFunction(ba_crc_hqx, "Oi",
                                    (PyObject *)pydata, 0);
  }
  if (PyErr_Occurred()) PyErr_Clear();
}

// OP_BINASCII_ROUNDTRIP: binascii.hexlify(data) then binascii.unhexlify()
// on the result. Exercises both directions of hex encoding.
static void op_binascii_roundtrip(FuzzedDataProvider &fdp) {
  std::string data = fdp.ConsumeRemainingBytesAsString();
  PyRef pydata = PyBytes_FromStringAndSize(Y(data));
  CHECK(pydata);
  PyRef hexed = PyObject_CallFunction(ba_hexlify, "O",
                                      (PyObject *)pydata);
  CHECK(hexed);
  PyRef r = PyObject_CallFunction(ba_unhexlify, "O", (PyObject *)hexed);
  if (PyErr_Occurred()) PyErr_Clear();
}

// ---------------------------------------------------------------------------
// Dispatch.
// ---------------------------------------------------------------------------

enum Op {
  OP_BINASCII_DECODE,
  OP_BINASCII_ENCODE,
  OP_BINASCII_CHECKSUM,
  OP_BINASCII_ROUNDTRIP,
  NUM_OPS
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  assert(Py_IsInitialized());
  init_binascii();
  if (size < 1 || size > kMaxInputSize) return 0;
  if (PyErr_Occurred()) PyErr_Clear();

  FuzzedDataProvider fdp(data, size);
  switch (fdp.ConsumeIntegralInRange<int>(0, NUM_OPS - 1)) {
    case OP_BINASCII_DECODE:
      op_binascii_decode(fdp);
      break;
    case OP_BINASCII_ENCODE:
      op_binascii_encode(fdp);
      break;
    case OP_BINASCII_CHECKSUM:
      op_binascii_checksum(fdp);
      break;
    case OP_BINASCII_ROUNDTRIP:
      op_binascii_roundtrip(fdp);
      break;
  }

  return 0;
}
