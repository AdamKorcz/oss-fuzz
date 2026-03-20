// fuzz_codecs.cpp — Fuzzer for CPython's codec C extension modules.
//
// This fuzzer exercises the following CPython C extension modules via
// their Python API, called through the Python C API from C++:
//
//   _multibytecodec,
//   _codecs_jp, _codecs_cn, _codecs_kr,
//   _codecs_hk, _codecs_tw, _codecs_iso2022
//                       — codecs.decode() with 17 codecs including shift_jis,
//                         euc-jp, gb2312, big5, gb18030, iso-2022-jp, etc.
//                         codecs.encode() with 19 codecs.
//                         Incremental decoders (shift_jis, gb18030, utf-16):
//                         split input at midpoint, decode halves, getstate, reset.
//                         Incremental encoders (shift_jis, utf-8):
//                         split string at midpoint, encode, reset, getstate.
//                         StreamReader: codecs.getreader('utf-8')(BytesIO).read()
//
// The first byte of fuzz input selects one of 5 operation types. Each
// operation consumes further bytes via FuzzedDataProvider to parameterize
// the call (codec selection, encoding method, data splits).
//
// All module functions are imported once during init and cached as static
// PyObject* pointers. PyRef (RAII) prevents reference leaks.
// Max input size: 1 MB.

#include "fuzz_helpers.h"

// ---------------------------------------------------------------------------
// Cached module objects, initialized once.
// ---------------------------------------------------------------------------

static PyObject *codecs_decode, *codecs_encode;
static PyObject *codecs_getincrementaldecoder, *codecs_getincrementalencoder;
static PyObject *codecs_getreader;
static PyObject *bytesio_ctor;

static int initialized = 0;

static void init_codecs(void) {
  if (initialized) return;

  codecs_decode = import_attr("codecs", "decode");
  codecs_encode = import_attr("codecs", "encode");
  codecs_getincrementaldecoder = import_attr("codecs",
                                             "getincrementaldecoder");
  codecs_getincrementalencoder = import_attr("codecs",
                                             "getincrementalencoder");
  codecs_getreader = import_attr("codecs", "getreader");
  bytesio_ctor = import_attr("io", "BytesIO");
  assert(!PyErr_Occurred());
  initialized = 1;
}

// ---------------------------------------------------------------------------
// Operations (5 ops)
// ---------------------------------------------------------------------------

// Codec names for OP_CODECS_DECODE: 17 decoders covering multibyte CJK
// codecs plus single-byte and Unicode escape codecs.
static const char *kCodecDecoders[] = {
  "utf-7", "shift_jis", "euc-jp", "gb2312", "big5", "iso-2022-jp",
  "euc-kr", "gb18030", "big5hkscs", "charmap", "ascii", "latin-1",
  "cp1252", "unicode_escape", "raw_unicode_escape", "utf-16", "utf-32",
};
static constexpr int kNumCodecDecoders =
    sizeof(kCodecDecoders) / sizeof(kCodecDecoders[0]);

// Codec names for OP_CODECS_ENCODE: 19 encoders covering multibyte CJK
// codecs plus Unicode, UTF, and single-byte encoders.
static const char *kCodecEncoders[] = {
  "shift_jis", "euc-jp", "gb2312", "big5", "iso-2022-jp", "euc-kr",
  "gb18030", "big5hkscs", "unicode_escape", "raw_unicode_escape",
  "utf-7", "utf-8", "utf-16", "utf-16-le", "utf-16-be", "utf-32",
  "latin-1", "ascii", "charmap",
};
static constexpr int kNumCodecEncoders =
    sizeof(kCodecEncoders) / sizeof(kCodecEncoders[0]);

// OP_CODECS_DECODE: Call codecs.decode(bytes, codec, 'replace') with a
// fuzz-chosen codec from 17 decoders.
static void op_codecs_decode(FuzzedDataProvider &fdp) {
  int ci = fdp.ConsumeIntegralInRange<int>(0, kNumCodecDecoders - 1);
  std::string data = fdp.ConsumeRemainingBytesAsString();
  PyRef pydata = PyBytes_FromStringAndSize(Y(data));
  CHECK(pydata);
  PyRef r = PyObject_CallFunction(codecs_decode, "Oss",
                                  (PyObject *)pydata,
                                  kCodecDecoders[ci], "replace");
  if (PyErr_Occurred()) PyErr_Clear();
}

// OP_CODECS_ENCODE: Convert fuzz bytes to a Python str, then call
// codecs.encode(str, codec, 'replace') with a fuzz-chosen codec.
static void op_codecs_encode(FuzzedDataProvider &fdp) {
  int ci = fdp.ConsumeIntegralInRange<int>(0, kNumCodecEncoders - 1);
  int str_enc = fdp.ConsumeIntegralInRange<int>(0, 3);
  if (fdp.remaining_bytes() == 0) return;
  size_t data_len = fdp.ConsumeIntegralInRange<size_t>(
      1, std::min(fdp.remaining_bytes(), (size_t)10000));
  std::string data = fdp.ConsumeBytesAsString(data_len);
  PyRef pystr(fuzz_bytes_to_str(data, str_enc));
  CHECK(pystr);
  PyRef r = PyObject_CallFunction(codecs_encode, "Oss",
                                  (PyObject *)pystr,
                                  kCodecEncoders[ci], "replace");
  if (PyErr_Occurred()) PyErr_Clear();
}

// OP_CODECS_INCREMENTAL_DECODE: Get an IncrementalDecoder for a fuzz-chosen
// codec, split the fuzz data at the midpoint, decode halves, getstate, reset.
static void op_codecs_incremental_decode(FuzzedDataProvider &fdp) {
  static const char *kIncCodecs[] = {"shift_jis", "gb18030", "utf-16"};
  int ci = fdp.ConsumeIntegralInRange<int>(0, 2);
  std::string data = fdp.ConsumeRemainingBytesAsString();
  size_t mid = fdp.ConsumeIntegralInRange<size_t>(0, data.size());

  PyRef codec_name = PyUnicode_FromString(kIncCodecs[ci]);
  CHECK(codec_name);
  PyRef decoder_factory = PyObject_CallFunction(
      codecs_getincrementaldecoder, "O", (PyObject *)codec_name);
  CHECK(decoder_factory);

  PyRef decoder = PyObject_CallFunction(decoder_factory, "s", "replace");
  CHECK(decoder);

  PyRef half1 = PyBytes_FromStringAndSize(data.data(), mid);
  CHECK(half1);
  PyRef r1 = PyObject_CallMethod(decoder, "decode", "O",
                                 (PyObject *)half1);
  if (!r1) {
    PyErr_Clear();
    return;
  }

  PyRef half2 = PyBytes_FromStringAndSize(data.data() + mid,
                                          data.size() - mid);
  CHECK(half2);
  PyRef r2 = PyObject_CallMethod(decoder, "decode", "Oi",
                                 (PyObject *)half2, 1);
  if (PyErr_Occurred()) PyErr_Clear();

  PyRef state = PyObject_CallMethod(decoder, "getstate", NULL);
  if (PyErr_Occurred()) PyErr_Clear();
  PyRef reset = PyObject_CallMethod(decoder, "reset", NULL);
  if (PyErr_Occurred()) PyErr_Clear();
}

// OP_CODECS_INCREMENTAL_ENCODE: Get an IncrementalEncoder for a fuzz-chosen
// codec, split str at midpoint, encode halves, reset, getstate.
static void op_codecs_incremental_encode(FuzzedDataProvider &fdp) {
  static const char *kIncCodecs[] = {"shift_jis", "utf-8"};
  int ci = fdp.ConsumeIntegralInRange<int>(0, 1);
  int str_enc = fdp.ConsumeIntegralInRange<int>(0, 3);
  if (fdp.remaining_bytes() == 0) return;
  size_t data_len = fdp.ConsumeIntegralInRange<size_t>(
      1, std::min(fdp.remaining_bytes(), (size_t)10000));
  std::string data = fdp.ConsumeBytesAsString(data_len);

  PyRef pystr(fuzz_bytes_to_str(data, str_enc));
  CHECK(pystr);
  Py_ssize_t slen = PyUnicode_GET_LENGTH(pystr);
  Py_ssize_t mid = fdp.ConsumeIntegralInRange<Py_ssize_t>(0, slen);

  PyRef codec_name = PyUnicode_FromString(kIncCodecs[ci]);
  CHECK(codec_name);
  PyRef encoder_factory = PyObject_CallFunction(
      codecs_getincrementalencoder, "O", (PyObject *)codec_name);
  CHECK(encoder_factory);

  PyRef encoder = PyObject_CallFunction(encoder_factory, "s", "replace");
  CHECK(encoder);

  PyRef half1 = PyUnicode_Substring(pystr, 0, mid);
  CHECK(half1);
  PyRef r1 = PyObject_CallMethod(encoder, "encode", "O",
                                 (PyObject *)half1);
  if (!r1) {
    PyErr_Clear();
    return;
  }

  PyRef reset_r = PyObject_CallMethod(encoder, "reset", NULL);
  if (PyErr_Occurred()) PyErr_Clear();

  PyRef half2 = PyUnicode_Substring(pystr, mid, slen);
  CHECK(half2);
  PyRef r2 = PyObject_CallMethod(encoder, "encode", "O",
                                 (PyObject *)half2);
  if (PyErr_Occurred()) PyErr_Clear();

  PyRef state = PyObject_CallMethod(encoder, "getstate", NULL);
  if (PyErr_Occurred()) PyErr_Clear();
}

// OP_CODECS_STREAM: Wrap fuzz data in BytesIO, create a UTF-8 StreamReader,
// then .read(). Exercises the StreamReader code path.
static void op_codecs_stream(FuzzedDataProvider &fdp) {
  std::string data = fdp.ConsumeRemainingBytesAsString();
  PyRef pydata = PyBytes_FromStringAndSize(Y(data));
  CHECK(pydata);
  PyRef bio = PyObject_CallFunction(bytesio_ctor, "O",
                                    (PyObject *)pydata);
  CHECK(bio);

  PyRef reader_factory = PyObject_CallFunction(
      codecs_getreader, "s", "utf-8");
  CHECK(reader_factory);

  PyRef reader = PyObject_CallFunction(reader_factory, "Os",
                                       (PyObject *)bio, "replace");
  CHECK(reader);

  PyRef r = PyObject_CallMethod(reader, "read", NULL);
  if (PyErr_Occurred()) PyErr_Clear();
}

// ---------------------------------------------------------------------------
// Dispatch.
// ---------------------------------------------------------------------------

enum Op {
  OP_CODECS_DECODE,
  OP_CODECS_ENCODE,
  OP_CODECS_INCREMENTAL_DECODE,
  OP_CODECS_INCREMENTAL_ENCODE,
  OP_CODECS_STREAM,
  NUM_OPS
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  assert(Py_IsInitialized());
  init_codecs();
  if (size < 1 || size > kMaxInputSize) return 0;
  if (PyErr_Occurred()) PyErr_Clear();

  FuzzedDataProvider fdp(data, size);
  switch (fdp.ConsumeIntegralInRange<int>(0, NUM_OPS - 1)) {
    case OP_CODECS_DECODE:
      op_codecs_decode(fdp);
      break;
    case OP_CODECS_ENCODE:
      op_codecs_encode(fdp);
      break;
    case OP_CODECS_INCREMENTAL_DECODE:
      op_codecs_incremental_decode(fdp);
      break;
    case OP_CODECS_INCREMENTAL_ENCODE:
      op_codecs_incremental_encode(fdp);
      break;
    case OP_CODECS_STREAM:
      op_codecs_stream(fdp);
      break;
  }

  return 0;
}
