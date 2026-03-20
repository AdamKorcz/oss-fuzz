from fuzz_dp import FuzzedDataProvider
import ctypes

def FuzzerRunOne(FuzzerInput):
    if len(FuzzerInput) < 1 or len(FuzzerInput) > 0x10000:
        return
    fdp = FuzzedDataProvider(FuzzerInput)
    target = fdp.ConsumeIntInRange(0, 5)
    try:
        if target == 0:
            data = fdp.ConsumeBytes(fdp.remaining_bytes())
            if len(data) >= ctypes.sizeof(ctypes.c_char):
                ctypes.c_char.from_buffer_copy(data[:ctypes.sizeof(ctypes.c_char)])
        elif target == 1:
            data = fdp.ConsumeBytes(fdp.remaining_bytes())
            if len(data) >= ctypes.sizeof(ctypes.c_int):
                ctypes.c_int.from_buffer_copy(data[:ctypes.sizeof(ctypes.c_int)])
        elif target == 2:
            data = fdp.ConsumeBytes(fdp.remaining_bytes())
            if len(data) >= ctypes.sizeof(ctypes.c_double):
                ctypes.c_double.from_buffer_copy(data[:ctypes.sizeof(ctypes.c_double)])
        elif target == 3:
            n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 10000)) if fdp.remaining_bytes() > 0 else 0
            if n > 0:
                data = fdp.ConsumeBytes(n)
                ctypes.create_string_buffer(data)
        elif target == 4:
            data = fdp.ConsumeBytes(fdp.remaining_bytes())
            if len(data) >= ctypes.sizeof(ctypes.c_float):
                ctypes.c_float.from_buffer_copy(data[:ctypes.sizeof(ctypes.c_float)])
        elif target == 5:
            data = fdp.ConsumeBytes(fdp.remaining_bytes())
            if len(data) >= ctypes.sizeof(ctypes.c_longlong):
                ctypes.c_longlong.from_buffer_copy(data[:ctypes.sizeof(ctypes.c_longlong)])
    except Exception:
        pass
