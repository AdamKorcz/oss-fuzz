// fuzz_compression.cpp — Fuzzer for CPython's compression C extension modules.
//
// This fuzzer exercises the following CPython C extension modules via
// their Python API, called through the Python C API from C++:
//
//   zlib               — compress/decompress (one-shot and streaming via
//                         compressobj/decompressobj with wbits, zdict, copy,
//                         flush), crc32, adler32
//   _bz2               — BZ2Decompressor.decompress(), bz2.compress()
//   _lzma              — LZMADecompressor.decompress() with FORMAT_AUTO/XZ/ALONE
//                         and 16 MB memlimit, lzma.compress()
//
// The first byte of fuzz input selects one of 6 operation types. Each
// operation consumes further bytes via FuzzedDataProvider to parameterize
// the call (compression level, wbits value, format, boolean flags).
//
// All module functions and constructors are imported once during init and
// cached as static PyObject* pointers. PyRef (RAII) prevents reference leaks.
// Max input size: 1 MB.

#include "fuzz_helpers.h"

// ---------------------------------------------------------------------------
// Cached module objects, initialized once.
// ---------------------------------------------------------------------------

// zlib
static PyObject *zlib_compress, *zlib_decompress;
static PyObject *zlib_decompressobj, *zlib_compressobj;
static PyObject *zlib_crc32, *zlib_adler32;

// bz2
static PyObject *bz2_compress, *bz2_BZ2Decompressor;

// lzma
static PyObject *lzma_LZMADecompressor, *lzma_compress;
static long lzma_FORMAT_AUTO_val, lzma_FORMAT_XZ_val, lzma_FORMAT_ALONE_val;

static int initialized = 0;

static void init_compression(void) {
  if (initialized) return;

  // zlib
  zlib_compress = import_attr("zlib", "compress");
  zlib_decompress = import_attr("zlib", "decompress");
  zlib_decompressobj = import_attr("zlib", "decompressobj");
  zlib_compressobj = import_attr("zlib", "compressobj");
  zlib_crc32 = import_attr("zlib", "crc32");
  zlib_adler32 = import_attr("zlib", "adler32");

  // bz2
  bz2_compress = import_attr("bz2", "compress");
  bz2_BZ2Decompressor = import_attr("bz2", "BZ2Decompressor");

  // lzma
  lzma_LZMADecompressor = import_attr("lzma", "LZMADecompressor");
  lzma_compress = import_attr("lzma", "compress");
  {
    PyObject *v;
    v = import_attr("lzma", "FORMAT_AUTO");
    lzma_FORMAT_AUTO_val = PyLong_AsLong(v);
    Py_DECREF(v);
    v = import_attr("lzma", "FORMAT_XZ");
    lzma_FORMAT_XZ_val = PyLong_AsLong(v);
    Py_DECREF(v);
    v = import_attr("lzma", "FORMAT_ALONE");
    lzma_FORMAT_ALONE_val = PyLong_AsLong(v);
    Py_DECREF(v);
  }

  assert(!PyErr_Occurred());
  initialized = 1;
}

// ---------------------------------------------------------------------------
// Operations (6 ops)
// ---------------------------------------------------------------------------

// OP_ZLIB_DECOMPRESS: Create a zlib.decompressobj with fuzz-chosen wbits
// from {-15 (raw), 0 (auto), 15 (zlib), 31 (gzip), 47 (auto-detect)} and
// an optional zdict (first 32 bytes of data). Call .decompress(data, 1MB),
// optionally .flush(), and optionally .copy() + decompress on the copy.
// Exercises Decomp_Type, zlib_Decompress_decompress, copy, flush paths.
static void op_zlib_decompress(FuzzedDataProvider &fdp) {
  static const int kWbitsChoices[] = {-15, 0, 15, 31, 47};
  int wbits = kWbitsChoices[fdp.ConsumeIntegralInRange<int>(0, 4)];
  bool use_zdict = fdp.ConsumeBool();
  size_t zdict_size = fdp.ConsumeIntegralInRange<size_t>(1, 32768);
  std::string data = fdp.ConsumeRemainingBytesAsString();

  PyRef kwargs = PyDict_New();
  CHECK(kwargs);
  PyRef wbits_obj = PyLong_FromLong(wbits);
  CHECK(wbits_obj);
  PyRef args_dobj = PyTuple_Pack(1, (PyObject *)wbits_obj);
  CHECK(args_dobj);

  if (use_zdict && data.size() > zdict_size) {
    PyRef zdict = PyBytes_FromStringAndSize(data.data(), zdict_size);
    CHECK(zdict);
    PyDict_SetItemString(kwargs, "zdict", zdict);
    data = data.substr(zdict_size);
  }

  PyRef dobj = PyObject_Call(zlib_decompressobj, args_dobj, kwargs);
  CHECK(dobj);

  PyRef pydata = PyBytes_FromStringAndSize(Y(data));
  CHECK(pydata);
  PyRef r = PyObject_CallMethod(dobj, "decompress", "Oi",
                                (PyObject *)pydata, 1048576);
  if (!r) {
    PyErr_Clear();
    return;
  }

  if (data.size() % 2 == 0) {
    PyRef flush_r = PyObject_CallMethod(dobj, "flush", NULL);
    if (PyErr_Occurred()) PyErr_Clear();
  }

  if (data.size() % 3 == 0) {
    PyRef copy_obj = PyObject_CallMethod(dobj, "copy", NULL);
    if (copy_obj) {
      PyRef r2 = PyObject_CallMethod(copy_obj, "decompress", "Oi",
                                     (PyObject *)pydata, 1048576);
      if (PyErr_Occurred()) PyErr_Clear();
    } else {
      PyErr_Clear();
    }
  }
}

// OP_ZLIB_COMPRESS: Either one-shot zlib.compress(data, level) or streaming
// via compressobj(level).compress(data).flush(), with optional .copy().flush().
// Level is fuzz-chosen 0-9. Exercises Compress_Type and zlib_compress_impl.
static void op_zlib_compress(FuzzedDataProvider &fdp) {
  int level = fdp.ConsumeIntegralInRange<int>(0, 9);
  bool use_obj = fdp.ConsumeBool();
  if (fdp.remaining_bytes() == 0) return;
  size_t data_len = fdp.ConsumeIntegralInRange<size_t>(
      1, std::min(fdp.remaining_bytes(), (size_t)10000));
  std::string data = fdp.ConsumeBytesAsString(data_len);

  PyRef pydata = PyBytes_FromStringAndSize(Y(data));
  CHECK(pydata);

  if (use_obj) {
    PyRef cobj = PyObject_CallFunction(zlib_compressobj, "i", level);
    CHECK(cobj);
    PyRef r1 = PyObject_CallMethod(cobj, "compress", "O",
                                   (PyObject *)pydata);
    CHECK(r1);
    if (data.size() % 2 == 0) {
      PyRef copy_obj = PyObject_CallMethod(cobj, "copy", NULL);
      if (copy_obj) {
        PyRef r2 = PyObject_CallMethod(copy_obj, "flush", NULL);
        if (PyErr_Occurred()) PyErr_Clear();
      } else {
        PyErr_Clear();
      }
    }
    PyRef r3 = PyObject_CallMethod(cobj, "flush", NULL);
    if (PyErr_Occurred()) PyErr_Clear();
  } else {
    PyRef r = PyObject_CallFunction(zlib_compress, "Oi",
                                    (PyObject *)pydata, level);
    if (PyErr_Occurred()) PyErr_Clear();
  }
}

// OP_ZLIB_CHECKSUM: Call either zlib.crc32(data) or zlib.adler32(data),
// fuzz-chosen. Exercises the checksum C implementations in zlibmodule.c.
static void op_zlib_checksum(FuzzedDataProvider &fdp) {
  bool use_crc = fdp.ConsumeBool();
  std::string data = fdp.ConsumeRemainingBytesAsString();
  PyRef pydata = PyBytes_FromStringAndSize(Y(data));
  CHECK(pydata);
  PyRef r = PyObject_CallFunction(
      use_crc ? zlib_crc32 : zlib_adler32, "O", (PyObject *)pydata);
  if (PyErr_Occurred()) PyErr_Clear();
}

// OP_BZ2: Either bz2.compress(data) or BZ2Decompressor().decompress(data, 1MB),
// fuzz-chosen. Exercises the _bz2 C extension (BZ2Compressor/BZ2Decompressor).
static void op_bz2(FuzzedDataProvider &fdp) {
  bool do_compress = fdp.ConsumeBool();
  if (fdp.remaining_bytes() == 0) return;
  size_t data_len = fdp.ConsumeIntegralInRange<size_t>(
      1, std::min(fdp.remaining_bytes(), (size_t)10000));
  std::string data = fdp.ConsumeBytesAsString(data_len);
  PyRef pydata = PyBytes_FromStringAndSize(Y(data));
  CHECK(pydata);

  if (do_compress) {
    PyRef r = PyObject_CallFunction(bz2_compress, "O",
                                    (PyObject *)pydata);
    if (PyErr_Occurred()) PyErr_Clear();
  } else {
    PyRef dobj = PyObject_CallFunction(bz2_BZ2Decompressor, NULL);
    CHECK(dobj);
    PyRef r = PyObject_CallMethod(dobj, "decompress", "Oi",
                                  (PyObject *)pydata, 1048576);
    if (PyErr_Occurred()) PyErr_Clear();
  }
}

// OP_LZMA_DECOMPRESS: Create LZMADecompressor with fuzz-chosen format from
// {FORMAT_AUTO, FORMAT_XZ, FORMAT_ALONE} and 16 MB memlimit, then call
// .decompress(data, 1MB). Exercises the _lzma C extension decompressor.
static void op_lzma_decompress(FuzzedDataProvider &fdp) {
  long fmt_vals[] = {
    lzma_FORMAT_AUTO_val, lzma_FORMAT_XZ_val, lzma_FORMAT_ALONE_val,
  };
  long fmt = fmt_vals[fdp.ConsumeIntegralInRange<int>(0, 2)];
  if (fdp.remaining_bytes() == 0) return;
  size_t data_len = fdp.ConsumeIntegralInRange<size_t>(
      1, std::min(fdp.remaining_bytes(), (size_t)10000));
  std::string data = fdp.ConsumeBytesAsString(data_len);
  PyRef pydata = PyBytes_FromStringAndSize(Y(data));
  CHECK(pydata);

  PyRef kwargs = PyDict_New();
  CHECK(kwargs);
  PyRef fmt_obj = PyLong_FromLong(fmt);
  CHECK(fmt_obj);
  PyDict_SetItemString(kwargs, "format", fmt_obj);
  PyRef memlimit = PyLong_FromLong(16 * 1024 * 1024);
  CHECK(memlimit);
  PyDict_SetItemString(kwargs, "memlimit", memlimit);

  PyRef empty_args = PyTuple_New(0);
  CHECK(empty_args);
  PyRef dobj = PyObject_Call(lzma_LZMADecompressor, empty_args, kwargs);
  CHECK(dobj);

  PyRef r = PyObject_CallMethod(dobj, "decompress", "Oi",
                                (PyObject *)pydata, 1048576);
  if (PyErr_Occurred()) PyErr_Clear();
}

// OP_LZMA_COMPRESS: One-shot lzma.compress(data). Exercises the _lzma
// C extension compressor with default settings.
static void op_lzma_compress(FuzzedDataProvider &fdp) {
  if (fdp.remaining_bytes() == 0) return;
  size_t data_len = fdp.ConsumeIntegralInRange<size_t>(
      1, std::min(fdp.remaining_bytes(), (size_t)10000));
  std::string data = fdp.ConsumeBytesAsString(data_len);
  PyRef pydata = PyBytes_FromStringAndSize(Y(data));
  CHECK(pydata);
  PyRef r = PyObject_CallFunction(lzma_compress, "O", (PyObject *)pydata);
  if (PyErr_Occurred()) PyErr_Clear();
}

// ---------------------------------------------------------------------------
// Dispatch.
// ---------------------------------------------------------------------------

enum Op {
  OP_ZLIB_DECOMPRESS,
  OP_ZLIB_COMPRESS,
  OP_ZLIB_CHECKSUM,
  OP_BZ2,
  OP_LZMA_DECOMPRESS,
  OP_LZMA_COMPRESS,
  NUM_OPS
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  assert(Py_IsInitialized());
  init_compression();
  if (size < 1 || size > kMaxInputSize) return 0;
  if (PyErr_Occurred()) PyErr_Clear();

  FuzzedDataProvider fdp(data, size);
  switch (fdp.ConsumeIntegralInRange<int>(0, NUM_OPS - 1)) {
    case OP_ZLIB_DECOMPRESS:
      op_zlib_decompress(fdp);
      break;
    case OP_ZLIB_COMPRESS:
      op_zlib_compress(fdp);
      break;
    case OP_ZLIB_CHECKSUM:
      op_zlib_checksum(fdp);
      break;
    case OP_BZ2:
      op_bz2(fdp);
      break;
    case OP_LZMA_DECOMPRESS:
      op_lzma_decompress(fdp);
      break;
    case OP_LZMA_COMPRESS:
      op_lzma_compress(fdp);
      break;
  }

  return 0;
}
