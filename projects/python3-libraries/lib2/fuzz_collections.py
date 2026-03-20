from fuzz_dp import FuzzedDataProvider
import collections

def op_count_elements(fdp):
    n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 10000)) if fdp.remaining_bytes() > 0 else 0
    if n == 0:
        return
    s = fdp.ConsumeBytes(n).decode('latin-1')
    d = {}
    collections._count_elements(d, s)

def op_deque(fdp):
    maxlen = fdp.ConsumeIntInRange(0, 100) if fdp.ConsumeBool() else None
    # Init from iterable to exercise deque_init
    init_n = fdp.ConsumeIntInRange(0, min(fdp.remaining_bytes(), 50))
    init_data = fdp.ConsumeIntList(init_n, 1)
    dq = collections.deque(init_data, maxlen=maxlen)
    num_ops = fdp.ConsumeIntInRange(1, 30)
    for _ in range(num_ops):
        if fdp.remaining_bytes() == 0:
            break
        op = fdp.ConsumeIntInRange(0, 14)
        if op == 0:
            dq.append(fdp.ConsumeInt(1))
        elif op == 1:
            dq.appendleft(fdp.ConsumeInt(1))
        elif op == 2 and len(dq) > 0:
            dq.pop()
        elif op == 3 and len(dq) > 0:
            dq.popleft()
        elif op == 4:
            n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 50))
            dq.extend(fdp.ConsumeIntList(n, 1))
        elif op == 5:
            n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 50))
            dq.extendleft(fdp.ConsumeIntList(n, 1))
        elif op == 6:
            dq.rotate(fdp.ConsumeIntInRange(-10, 10))
        elif op == 7:
            dq.reverse()
        elif op == 8:
            dq.count(fdp.ConsumeInt(1))
        elif op == 9 and len(dq) > 0:
            try:
                dq.index(fdp.ConsumeInt(1))
            except ValueError:
                pass
        elif op == 10 and len(dq) > 0:
            try:
                dq.remove(dq[0])
            except ValueError:
                pass
        elif op == 11:
            dq.clear()
        elif op == 12:
            dq.copy()
        elif op == 13:
            dq2 = collections.deque(fdp.ConsumeIntList(
                fdp.ConsumeIntInRange(0, min(fdp.remaining_bytes(), 20)), 1))
            _ = dq == dq2
            _ = dq < dq2
        elif op == 14:
            _ = list(dq)
            _ = len(dq)
            _ = bool(dq)

def op_defaultdict(fdp):
    dd = collections.defaultdict(int)
    num_ops = fdp.ConsumeIntInRange(1, 20)
    for _ in range(num_ops):
        if fdp.remaining_bytes() == 0:
            break
        op = fdp.ConsumeIntInRange(0, 3)
        key = fdp.ConsumeBytes(fdp.ConsumeIntInRange(1, 10)).decode('latin-1')
        if op == 0:
            dd[key] += fdp.ConsumeInt(1)
        elif op == 1:
            _ = dd[key]
        elif op == 2:
            _ = key in dd
        elif op == 3:
            dd.pop(key, None)

def op_ordered_dict(fdp):
    od = collections.OrderedDict()
    num_ops = fdp.ConsumeIntInRange(1, 20)
    for _ in range(num_ops):
        if fdp.remaining_bytes() == 0:
            break
        op = fdp.ConsumeIntInRange(0, 5)
        key = fdp.ConsumeBytes(fdp.ConsumeIntInRange(1, 10)).decode('latin-1')
        if op == 0:
            od[key] = fdp.ConsumeInt(1)
        elif op == 1:
            od.pop(key, None)
        elif op == 2:
            od.move_to_end(key, last=fdp.ConsumeBool()) if key in od else None
        elif op == 3:
            _ = list(od.keys())
        elif op == 4:
            _ = list(reversed(od))
        elif op == 5 and len(od) > 0:
            od.popitem(last=fdp.ConsumeBool())

def FuzzerRunOne(FuzzerInput):
    if len(FuzzerInput) < 1 or len(FuzzerInput) > 0x10000:
        return
    fdp = FuzzedDataProvider(FuzzerInput)
    op = fdp.ConsumeIntInRange(0, 3)
    try:
        if op == 0:
            op_count_elements(fdp)
        elif op == 1:
            op_deque(fdp)
        elif op == 2:
            op_defaultdict(fdp)
        else:
            op_ordered_dict(fdp)
    except Exception:
        pass
