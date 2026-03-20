from fuzz_dp import FuzzedDataProvider
import json

def build_container(fdp):
    ctype = fdp.ConsumeIntInRange(0, 5)
    if ctype == 0:
        n = fdp.ConsumeIntInRange(0, min(fdp.remaining_bytes(), 200))
        return fdp.ConsumeIntList(n, 1)
    elif ctype == 1:
        n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 1000)) if fdp.remaining_bytes() > 0 else 0
        return fdp.ConsumeBytes(n).decode('latin-1') if n > 0 else ""
    elif ctype == 2:
        n = fdp.ConsumeIntInRange(0, min(fdp.remaining_bytes(), 50))
        d = {}
        for _ in range(n):
            if fdp.remaining_bytes() == 0:
                break
            kn = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 20))
            key = fdp.ConsumeBytes(kn).decode('latin-1')
            val = fdp.ConsumeInt(1)
            d[key] = val
        return d
    elif ctype == 3:
        n = fdp.ConsumeIntInRange(0, min(fdp.remaining_bytes(), 200))
        return tuple(fdp.ConsumeIntList(n, 1))
    elif ctype == 4:
        return fdp.ConsumeFloat()
    else:
        return fdp.ConsumeInt(4)

def FuzzerRunOne(FuzzerInput):
    if len(FuzzerInput) < 1 or len(FuzzerInput) > 0x100000:
        return
    fdp = FuzzedDataProvider(FuzzerInput)
    target = fdp.ConsumeIntInRange(0, 5)
    try:
        obj = build_container(fdp)
        if target == 0:
            json.dumps(obj)
        elif target == 1:
            json.dumps(obj, ensure_ascii=True)
        elif target == 2:
            json.dumps(obj, ensure_ascii=False)
        elif target == 3:
            json.dumps(obj, sort_keys=True)
        elif target == 4:
            indent = fdp.ConsumeIntInRange(0, 8)
            json.dumps(obj, indent=indent)
        else:
            enc = json.JSONEncoder(
                ensure_ascii=fdp.ConsumeBool(),
                sort_keys=fdp.ConsumeBool(),
                indent=fdp.ConsumeIntInRange(0, 4) if fdp.ConsumeBool() else None,
            )
            enc.encode(obj)
    except (ValueError, TypeError, RecursionError, OverflowError):
        pass
    except Exception:
        pass
