from fuzz_dp import FuzzedDataProvider
import os
import mmap
import tempfile

def FuzzerRunOne(FuzzerInput):
    if len(FuzzerInput) < 1 or len(FuzzerInput) > 0x10000:
        return
    fdp = FuzzedDataProvider(FuzzerInput)
    init_size = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 4096)) if fdp.remaining_bytes() > 0 else 0
    if init_size == 0:
        return
    init_data = fdp.ConsumeBytes(init_size)
    tmpname = None
    try:
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmpname = tmp.name
            tmp.write(init_data)
            tmp.flush()

        with open(tmpname, 'r+b') as f:
            mm = mmap.mmap(f.fileno(), 0)
            num_ops = fdp.ConsumeIntInRange(1, 10)
            for _ in range(num_ops):
                if fdp.remaining_bytes() == 0:
                    break
                op = fdp.ConsumeIntInRange(0, 9)
                if op == 0:
                    needle = fdp.ConsumeBytes(fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 20)))
                    mm.find(needle)
                elif op == 1:
                    needle = fdp.ConsumeBytes(fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 20)))
                    mm.rfind(needle)
                elif op == 2:
                    mm.seek(0)
                    mm.read(min(len(mm), 100))
                elif op == 3:
                    mm.seek(0)
                    mm.readline()
                elif op == 4:
                    pos = fdp.ConsumeIntInRange(0, max(0, len(mm) - 1))
                    mm.seek(pos)
                elif op == 5:
                    if len(mm) > 0:
                        idx = fdp.ConsumeIntInRange(0, len(mm) - 1)
                        _ = mm[idx]
                elif op == 6:
                    # write at current position
                    data = fdp.ConsumeBytes(fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 50)))
                    pos = fdp.ConsumeIntInRange(0, max(0, len(mm) - len(data)))
                    mm.seek(pos)
                    mm.write(data)
                elif op == 7:
                    # setitem
                    if len(mm) > 0:
                        idx = fdp.ConsumeIntInRange(0, len(mm) - 1)
                        mm[idx] = fdp.ConsumeIntInRange(0, 255)
                elif op == 8:
                    # move
                    if len(mm) > 1:
                        count = fdp.ConsumeIntInRange(1, len(mm) // 2)
                        src = fdp.ConsumeIntInRange(0, len(mm) - count)
                        dest = fdp.ConsumeIntInRange(0, len(mm) - count)
                        mm.move(dest, src, count)
                elif op == 9:
                    mm.flush()
            mm.close()
    except Exception:
        pass
    finally:
        if tmpname:
            try:
                os.unlink(tmpname)
            except Exception:
                pass
