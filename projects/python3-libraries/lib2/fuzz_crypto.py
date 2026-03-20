from fuzz_dp import FuzzedDataProvider
import hashlib
import hmac
import io

try:
    import _md5, _sha1, _sha2, _sha3, _blake2
    HASH_CTORS = [
        _md5.md5, _sha1.sha1,
        _sha2.sha224, _sha2.sha256, _sha2.sha384, _sha2.sha512,
        _sha3.sha3_224, _sha3.sha3_256, _sha3.sha3_384, _sha3.sha3_512,
        _blake2.blake2b, _blake2.blake2s,
    ]
    SHAKE_CTORS = [_sha3.shake_128, _sha3.shake_256]
except ImportError:
    HASH_CTORS = [
        hashlib.md5, hashlib.sha1,
        hashlib.sha224, hashlib.sha256, hashlib.sha384, hashlib.sha512,
        hashlib.sha3_224, hashlib.sha3_256, hashlib.sha3_384, hashlib.sha3_512,
        hashlib.blake2b, hashlib.blake2s,
    ]
    SHAKE_CTORS = [lambda d=b'': hashlib.new('shake_128', d),
                   lambda d=b'': hashlib.new('shake_256', d)]

HMAC_COMPUTE_FUNCS = []
try:
    import _hmac
    for name in ['compute_md5', 'compute_sha1', 'compute_sha256', 'compute_sha512']:
        if hasattr(_hmac, name):
            HMAC_COMPUTE_FUNCS.append(getattr(_hmac, name))
except ImportError:
    pass

HMAC_ALGOS = ['md5', 'sha224', 'sha256', 'sha384', 'sha512', 'sha3_256', 'blake2s']
PBKDF2_ALGOS = ['sha1', 'sha256', 'sha512']
HASHLIB_ALGOS = ['md5', 'sha256', 'sha3_256', 'sha512']

def chain_hash_actions(h, fdp):
    for _ in range(min(100, fdp.remaining_bytes())):
        if fdp.remaining_bytes() == 0:
            break
        action = fdp.ConsumeIntInRange(0, 4)
        if action == 0:
            n = fdp.ConsumeIntInRange(0, min(fdp.remaining_bytes(), 10000))
            h.update(fdp.ConsumeBytes(n))
        elif action == 1:
            h.digest()
        elif action == 2:
            h.hexdigest()
        elif action == 3:
            h.copy().digest()
        elif action == 4:
            _ = h.name
            _ = h.digest_size
            _ = h.block_size

def op_hash_chain(fdp):
    ctor = fdp.PickValueInList(HASH_CTORS)
    n = fdp.ConsumeIntInRange(0, 10000)
    init_data = fdp.ConsumeBytes(n)
    h = ctor(init_data)
    chain_hash_actions(h, fdp)

def op_shake_chain(fdp):
    ctor = fdp.PickValueInList(SHAKE_CTORS)
    n = fdp.ConsumeIntInRange(0, 10000)
    init_data = fdp.ConsumeBytes(n)
    h = ctor(init_data)
    for _ in range(min(100, fdp.remaining_bytes())):
        if fdp.remaining_bytes() == 0:
            break
        action = fdp.ConsumeIntInRange(0, 2)
        if action == 0:
            n2 = fdp.ConsumeIntInRange(0, min(fdp.remaining_bytes(), 10000))
            h.update(fdp.ConsumeBytes(n2))
        elif action == 1:
            length = fdp.ConsumeIntInRange(1, 10000)
            h.digest(length)
        elif action == 2:
            h2 = h.copy()
            length = fdp.ConsumeIntInRange(1, 10000)
            h2.digest(length)

def op_blake2_keyed(fdp, ctor, max_key, max_salt, max_person):
    key_len = fdp.ConsumeIntInRange(0, max_key)
    key = fdp.ConsumeBytes(key_len)
    salt_len = fdp.ConsumeIntInRange(0, max_salt)
    salt = fdp.ConsumeBytes(salt_len)
    person_len = fdp.ConsumeIntInRange(0, max_person)
    person = fdp.ConsumeBytes(person_len)
    n = fdp.ConsumeIntInRange(0, 10000)
    data = fdp.ConsumeBytes(n)
    h = ctor(data, key=key, salt=salt, person=person)
    chain_hash_actions(h, fdp)

def op_blake2_vardigest(fdp, ctor, max_ds):
    ds = fdp.ConsumeIntInRange(1, max_ds)
    n = fdp.ConsumeIntInRange(0, 10000)
    data = fdp.ConsumeBytes(n)
    h = ctor(data, digest_size=ds)
    chain_hash_actions(h, fdp)

def op_hmac_compute(fdp):
    if not HMAC_COMPUTE_FUNCS:
        return
    func = fdp.PickValueInList(HMAC_COMPUTE_FUNCS)
    key_len = fdp.ConsumeIntInRange(1, 10000)
    key = fdp.ConsumeBytes(key_len) or b'\x00'
    msg = fdp.ConsumeBytes(fdp.remaining_bytes())
    func(key, msg)

def op_pyhmac_chain(fdp):
    algo = fdp.PickValueInList(HMAC_ALGOS)
    key_len = fdp.ConsumeIntInRange(1, 10000)
    key = fdp.ConsumeBytes(key_len) or b'\x00'
    h = hmac.new(key, digestmod=algo)
    chain_hash_actions(h, fdp)

def op_hmac_digest(fdp):
    key_len = fdp.ConsumeIntInRange(1, 10000)
    key = fdp.ConsumeBytes(key_len) or b'\x00'
    msg = fdp.ConsumeBytes(fdp.remaining_bytes())
    hmac.digest(key, msg, 'sha256')

def op_hmac_compare(fdp):
    pad_size = fdp.ConsumeIntInRange(1, 128)
    data = fdp.ConsumeBytes(fdp.remaining_bytes())
    h = hmac.new(b'k', data, 'sha256')
    dig = h.digest()
    padded = data[:pad_size].ljust(pad_size, b'\x00')
    hmac.compare_digest(dig, padded)

def op_hashlib_chain(fdp):
    algo = fdp.PickValueInList(HASHLIB_ALGOS)
    n = fdp.ConsumeIntInRange(0, 10000)
    init_data = fdp.ConsumeBytes(n)
    h = hashlib.new(algo, init_data, usedforsecurity=False)
    chain_hash_actions(h, fdp)

def op_hashlib_file_digest(fdp):
    algo = fdp.PickValueInList(HASHLIB_ALGOS)
    data = fdp.ConsumeBytes(fdp.remaining_bytes())
    bio = io.BytesIO(data)
    h = hashlib.file_digest(bio, algo)
    h.hexdigest()

def op_pbkdf2(fdp):
    algo = fdp.PickValueInList(PBKDF2_ALGOS)
    salt_len = fdp.ConsumeIntInRange(1, 10000)
    salt = fdp.ConsumeBytes(salt_len) or b'\x00'
    pw = fdp.ConsumeBytes(fdp.remaining_bytes())
    hashlib.pbkdf2_hmac(algo, pw, salt, 1)

def FuzzerRunOne(FuzzerInput):
    if len(FuzzerInput) < 1 or len(FuzzerInput) > 0x100000:
        return
    fdp = FuzzedDataProvider(FuzzerInput)
    op = fdp.ConsumeIntInRange(0, 12)
    try:
        if op == 0:
            op_hash_chain(fdp)
        elif op == 1:
            op_shake_chain(fdp)
        elif op == 2:
            op_blake2_keyed(fdp, hashlib.blake2b, 64, 16, 16)
        elif op == 3:
            op_blake2_keyed(fdp, hashlib.blake2s, 32, 8, 8)
        elif op == 4:
            op_blake2_vardigest(fdp, hashlib.blake2b, 64)
        elif op == 5:
            op_blake2_vardigest(fdp, hashlib.blake2s, 32)
        elif op == 6:
            op_hmac_compute(fdp)
        elif op == 7:
            op_pyhmac_chain(fdp)
        elif op == 8:
            op_hmac_digest(fdp)
        elif op == 9:
            op_hmac_compare(fdp)
        elif op == 10:
            op_hashlib_chain(fdp)
        elif op == 11:
            op_hashlib_file_digest(fdp)
        elif op == 12:
            op_pbkdf2(fdp)
    except Exception:
        pass
