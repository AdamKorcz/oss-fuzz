from fuzz_dp import FuzzedDataProvider
import array

TYPECODES = list('bBhHiIlLqQfd')

def op_array_frombytes(fdp):
    tc = fdp.PickValueInList(TYPECODES)
    data = fdp.ConsumeBytes(fdp.remaining_bytes())
    a = array.array(tc)
    a.frombytes(data[:len(data) - len(data) % a.itemsize])
    a.tobytes()
    a.tolist()

def op_array_methods(fdp):
    tc = fdp.PickValueInList(TYPECODES)
    data = fdp.ConsumeBytes(fdp.remaining_bytes())
    a = array.array(tc)
    a.frombytes(data[:len(data) - len(data) % a.itemsize])
    if len(a) == 0:
        return
    num_ops = fdp.ConsumeIntInRange(1, 20)
    for _ in range(num_ops):
        if fdp.remaining_bytes() == 0:
            break
        op = fdp.ConsumeIntInRange(0, 7)
        if op == 0:
            a.reverse()
        elif op == 1:
            a.byteswap()
        elif op == 2 and len(a) > 0:
            a.pop()
        elif op == 3 and len(a) > 0:
            a.count(a[0])
        elif op == 4 and len(a) > 0:
            try:
                a.index(a[0])
            except ValueError:
                pass
        elif op == 5 and len(a) > 0:
            idx = fdp.ConsumeIntInRange(0, len(a) - 1)
            a.insert(idx, a[0])
        elif op == 6 and len(a) > 0:
            try:
                a.remove(a[0])
            except ValueError:
                pass
        elif op == 7:
            a.tobytes()

def op_array_slice(fdp):
    tc = fdp.PickValueInList(TYPECODES)
    data = fdp.ConsumeBytes(fdp.remaining_bytes())
    a = array.array(tc)
    a.frombytes(data[:len(data) - len(data) % a.itemsize])
    if len(a) < 2:
        return
    start = fdp.ConsumeIntInRange(0, len(a) - 1)
    end = fdp.ConsumeIntInRange(start, len(a))
    _ = a[start:end]
    b = array.array(tc, a[start:end])
    a[start:end] = b

def FuzzerRunOne(FuzzerInput):
    if len(FuzzerInput) < 1 or len(FuzzerInput) > 0x10000:
        return
    fdp = FuzzedDataProvider(FuzzerInput)
    op = fdp.ConsumeIntInRange(0, 2)
    try:
        if op == 0:
            op_array_frombytes(fdp)
        elif op == 1:
            op_array_methods(fdp)
        else:
            op_array_slice(fdp)
    except Exception:
        pass
