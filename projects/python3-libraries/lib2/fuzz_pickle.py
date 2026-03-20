from fuzz_dp import FuzzedDataProvider
import pickle
import io

class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        raise pickle.UnpicklingError('restricted')

class PersistentUnpickler(pickle.Unpickler):
    def persistent_load(self, pid):
        return pid
    def find_class(self, module, name):
        raise pickle.UnpicklingError('restricted')

def build_container(fdp, ctype):
    n = fdp.ConsumeIntInRange(0, min(fdp.remaining_bytes(), 200))
    if ctype == 0:
        return fdp.ConsumeBytes(n)
    elif ctype == 1:
        return fdp.ConsumeBytes(n).decode('latin-1')
    elif ctype == 2:
        return fdp.ConsumeIntList(n, 1)
    elif ctype == 3:
        return tuple(fdp.ConsumeIntList(n, 1))
    elif ctype == 4:
        return set(fdp.ConsumeIntList(n, 1))
    elif ctype == 5:
        return frozenset(fdp.ConsumeIntList(n, 1))
    elif ctype == 6:
        return bytearray(fdp.ConsumeBytes(n))
    elif ctype == 7:
        d = {}
        entries = fdp.ConsumeIntInRange(0, min(n, 64))
        for _ in range(entries):
            if fdp.remaining_bytes() == 0:
                break
            kn = fdp.ConsumeIntInRange(1, 20)
            key = fdp.ConsumeBytes(kn).decode('latin-1')
            val = fdp.ConsumeInt(4)
            d[key] = val
        return d
    return fdp.ConsumeBytes(n)

def op_dumps(fdp):
    ctype = fdp.ConsumeIntInRange(0, 7)
    protocol = fdp.ConsumeIntInRange(0, 5)
    fix_imports = fdp.ConsumeBool()
    obj = build_container(fdp, ctype)
    pickle.dumps(obj, protocol=protocol, fix_imports=fix_imports)

def op_loads(fdp):
    variant = fdp.ConsumeIntInRange(0, 2)
    data = fdp.ConsumeBytes(fdp.remaining_bytes())
    bio = io.BytesIO(data)
    if variant == 0:
        unpickler = RestrictedUnpickler(bio)
    elif variant == 1:
        unpickler = PersistentUnpickler(bio)
    else:
        unpickler = RestrictedUnpickler(bio, fix_imports=True, encoding='bytes')
    unpickler.load()

def op_pickler(fdp):
    protocol = fdp.ConsumeIntInRange(0, 5)
    n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 200)) if fdp.remaining_bytes() > 0 else 0
    if n == 0:
        return
    obj1 = fdp.ConsumeIntList(n, 1)
    s = fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, min(fdp.remaining_bytes(), 200))).decode('latin-1')
    bio = io.BytesIO()
    p = pickle.Pickler(bio, protocol)
    p.dump(obj1)
    p.clear_memo()
    p.dump(s)
    bio.getvalue()

def op_roundtrip(fdp):
    ctype = fdp.ConsumeIntInRange(0, 7)
    obj = build_container(fdp, ctype)
    dumped = pickle.dumps(obj)
    pickle.loads(dumped)

def FuzzerRunOne(FuzzerInput):
    if len(FuzzerInput) < 1 or len(FuzzerInput) > 0x100000:
        return
    fdp = FuzzedDataProvider(FuzzerInput)
    op = fdp.ConsumeIntInRange(0, 3)
    try:
        if op == 0:
            op_dumps(fdp)
        elif op == 1:
            op_loads(fdp)
        elif op == 2:
            op_pickler(fdp)
        else:
            op_roundtrip(fdp)
    except Exception:
        pass
