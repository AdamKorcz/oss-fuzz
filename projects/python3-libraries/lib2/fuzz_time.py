from fuzz_dp import FuzzedDataProvider
import time

FORMATS = [
    "%Y-%m-%d", "%Y-%m-%d %H:%M:%S", "%d/%m/%Y", "%m/%d/%Y",
    "%H:%M:%S", "%I:%M %p", "%c", "%x", "%X",
    "%A %B %d, %Y", "%j", "%U", "%W",
]

def FuzzerRunOne(FuzzerInput):
    if len(FuzzerInput) < 1 or len(FuzzerInput) > 0x10000:
        return
    fdp = FuzzedDataProvider(FuzzerInput)
    target = fdp.ConsumeIntInRange(0, 2)
    try:
        if target == 0:
            n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 1000)) if fdp.remaining_bytes() > 0 else 0
            if n > 0:
                fmt = fdp.ConsumeBytes(n).decode('latin-1')
                time.strftime(fmt)
        elif target == 1:
            fmt = fdp.PickValueInList(FORMATS)
            n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 1000)) if fdp.remaining_bytes() > 0 else 0
            if n > 0:
                s = fdp.ConsumeBytes(n).decode('latin-1')
                time.strptime(s, fmt)
        else:
            n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 1000)) if fdp.remaining_bytes() > 0 else 0
            if n > 0:
                fmt = fdp.ConsumeBytes(n).decode('latin-1')
                n2 = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 1000)) if fdp.remaining_bytes() > 0 else 0
                if n2 > 0:
                    s = fdp.ConsumeBytes(n2).decode('latin-1')
                    time.strptime(s, fmt)
    except (ValueError, OverflowError):
        pass
    except Exception:
        pass
