from fuzz_dp import FuzzedDataProvider
import operator

def op_comparisons(fdp):
    a = fdp.ConsumeInt(4)
    b = fdp.ConsumeInt(4)
    ops = [operator.lt, operator.le, operator.gt, operator.ge,
           operator.eq, operator.ne]
    op = fdp.PickValueInList(ops)
    op(a, b)

def op_arithmetic(fdp):
    a = fdp.ConsumeInt(4)
    b = fdp.ConsumeInt(4)
    ops = [operator.add, operator.sub, operator.mul, operator.mod,
           operator.floordiv, operator.truediv, operator.pow,
           operator.lshift, operator.rshift,
           operator.and_, operator.or_, operator.xor]
    op = fdp.PickValueInList(ops)
    if op in (operator.truediv, operator.floordiv, operator.mod) and b == 0:
        b = 1
    if op == operator.pow and (b > 100 or b < -100):
        b = b % 20
    if op in (operator.lshift, operator.rshift) and (b < 0 or b > 64):
        b = abs(b) % 64
    op(a, b)

def op_unary(fdp):
    a = fdp.ConsumeInt(4)
    ops = [operator.neg, operator.pos, operator.abs, operator.invert,
           operator.index]
    op = fdp.PickValueInList(ops)
    op(a)

def op_sequence(fdp):
    n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 100))
    lst = fdp.ConsumeIntList(n, 1)
    target = fdp.ConsumeIntInRange(0, 7)
    if target == 0:
        operator.contains(lst, fdp.ConsumeInt(1))
    elif target == 1:
        operator.countOf(lst, fdp.ConsumeInt(1))
    elif target == 2:
        try:
            operator.indexOf(lst, fdp.ConsumeInt(1))
        except ValueError:
            pass
    elif target == 3:
        idx = fdp.ConsumeIntInRange(0, max(len(lst) - 1, 0))
        operator.getitem(lst, idx)
    elif target == 4:
        operator.concat(lst, fdp.ConsumeIntList(fdp.ConsumeIntInRange(0, 10), 1))
    elif target == 5:
        idx = fdp.ConsumeIntInRange(0, max(len(lst) - 1, 0))
        operator.setitem(lst, idx, fdp.ConsumeInt(1))
    elif target == 6:
        idx = fdp.ConsumeIntInRange(0, max(len(lst) - 1, 0))
        operator.delitem(lst, idx)
    elif target == 7:
        operator.length_hint(lst)

def op_itemgetter(fdp):
    n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 50))
    lst = fdp.ConsumeIntList(n, 1)
    if not lst:
        return
    num_keys = fdp.ConsumeIntInRange(1, min(len(lst), 5))
    keys = [fdp.ConsumeIntInRange(0, len(lst) - 1) for _ in range(num_keys)]
    getter = operator.itemgetter(*keys) if len(keys) > 1 else operator.itemgetter(keys[0])
    getter(lst)

def op_attrgetter(fdp):
    class Obj:
        pass
    obj = Obj()
    attrs = ['x', 'y', 'z', 'w']
    for a in attrs:
        setattr(obj, a, fdp.ConsumeInt(1))
    num_attrs = fdp.ConsumeIntInRange(1, 3)
    chosen = [fdp.PickValueInList(attrs) for _ in range(num_attrs)]
    getter = operator.attrgetter(*chosen) if len(chosen) > 1 else operator.attrgetter(chosen[0])
    getter(obj)

def op_methodcaller(fdp):
    n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 100))
    s = fdp.ConsumeBytes(n).decode('latin-1')
    methods = ['upper', 'lower', 'strip', 'title', 'swapcase']
    method = fdp.PickValueInList(methods)
    caller = operator.methodcaller(method)
    caller(s)

def FuzzerRunOne(FuzzerInput):
    if len(FuzzerInput) < 1 or len(FuzzerInput) > 0x10000:
        return
    fdp = FuzzedDataProvider(FuzzerInput)
    op = fdp.ConsumeIntInRange(0, 6)
    try:
        if op == 0:
            op_comparisons(fdp)
        elif op == 1:
            op_arithmetic(fdp)
        elif op == 2:
            op_unary(fdp)
        elif op == 3:
            op_sequence(fdp)
        elif op == 4:
            op_itemgetter(fdp)
        elif op == 5:
            op_attrgetter(fdp)
        elif op == 6:
            op_methodcaller(fdp)
    except Exception:
        pass
