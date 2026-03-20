from fuzz_dp import FuzzedDataProvider
import locale

def FuzzerRunOne(FuzzerInput):
    if len(FuzzerInput) < 1 or len(FuzzerInput) > 0x10000:
        return
    fdp = FuzzedDataProvider(FuzzerInput)
    target = fdp.ConsumeIntInRange(0, 1)
    n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 10000)) if fdp.remaining_bytes() > 0 else 0
    if n == 0:
        return
    s = fdp.ConsumeUnicode(n)
    try:
        if target == 0:
            locale.strxfrm(s)
        else:
            n2 = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 10000)) if fdp.remaining_bytes() > 0 else 0
            s2 = fdp.ConsumeUnicode(n2) if n2 > 0 else ""
            locale.strcoll(s, s2)
    except Exception:
        pass
