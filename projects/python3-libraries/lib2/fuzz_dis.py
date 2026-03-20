from fuzz_dp import FuzzedDataProvider
import dis
import io

def FuzzerRunOne(FuzzerInput):
    if len(FuzzerInput) < 1 or len(FuzzerInput) > 0x10000:
        return
    fdp = FuzzedDataProvider(FuzzerInput)
    n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 10000)) if fdp.remaining_bytes() > 0 else 0
    if n == 0:
        return
    s = fdp.ConsumeUnicode(n)
    try:
        code = compile(s, '<fuzz>', 'exec')
        out = io.StringIO()
        dis.dis(code, file=out)
    except Exception:
        pass
