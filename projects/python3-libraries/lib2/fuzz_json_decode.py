from fuzz_dp import FuzzedDataProvider
import json

def FuzzerRunOne(FuzzerInput):
    if len(FuzzerInput) < 1 or len(FuzzerInput) > 0x100000:
        return
    fdp = FuzzedDataProvider(FuzzerInput)
    target = fdp.ConsumeIntInRange(0, 2)
    n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 10000)) if fdp.remaining_bytes() > 0 else 0
    if n == 0:
        return
    s = fdp.ConsumeBytes(n).decode('latin-1')
    try:
        if target == 0:
            json.loads(s)
        elif target == 1:
            dec = json.JSONDecoder()
            dec.decode(s)
        else:
            dec = json.JSONDecoder()
            dec.raw_decode(s)
    except (json.JSONDecodeError, ValueError, RecursionError):
        pass
    except Exception:
        pass
