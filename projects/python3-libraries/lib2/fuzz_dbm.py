from fuzz_dp import FuzzedDataProvider
import os
import dbm
import tempfile

def FuzzerRunOne(FuzzerInput):
    if len(FuzzerInput) < 1 or len(FuzzerInput) > 0x10000:
        return
    fdp = FuzzedDataProvider(FuzzerInput)
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            dbpath = os.path.join(tmpdir, 'fuzzdb')
            with dbm.open(dbpath, 'c') as db:
                num_ops = fdp.ConsumeIntInRange(1, 20)
                for _ in range(num_ops):
                    if fdp.remaining_bytes() == 0:
                        break
                    op = fdp.ConsumeIntInRange(0, 4)
                    if op == 0:
                        n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 100))
                        key = fdp.ConsumeBytes(n)
                        n2 = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 1000)) if fdp.remaining_bytes() > 0 else 0
                        val = fdp.ConsumeBytes(n2) if n2 > 0 else b''
                        db[key] = val
                    elif op == 1:
                        n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 100))
                        key = fdp.ConsumeBytes(n)
                        _ = db.get(key)
                    elif op == 2:
                        _ = list(db.keys())
                    elif op == 3:
                        n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 100))
                        key = fdp.ConsumeBytes(n)
                        if key in db:
                            del db[key]
                    elif op == 4:
                        for k in db:
                            _ = db[k]
                            break
    except Exception:
        pass
