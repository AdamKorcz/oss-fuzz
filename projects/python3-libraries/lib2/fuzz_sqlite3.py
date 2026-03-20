from fuzz_dp import FuzzedDataProvider
import sqlite3

class _Agg:
    def __init__(self):
        self.vals = []
    def step(self, v):
        self.vals.append(v)
    def finalize(self):
        return len(self.vals)

class _AdaptMe:
    def __init__(self, v):
        self.v = v

_identity_fn = lambda x: x
_auth_fn = lambda *a: sqlite3.SQLITE_OK
_collation_fn = lambda a, b: (a > b) - (a < b)
_adapter_fn = lambda a: str(a.v)

def FuzzerRunOne(FuzzerInput):
    if len(FuzzerInput) < 1 or len(FuzzerInput) > 0x10000:
        return
    fdp = FuzzedDataProvider(FuzzerInput)
    try:
        conn = sqlite3.connect(':memory:')
        conn.execute('PRAGMA max_page_count=100')

        func_name = ''
        agg_name = ''
        collation_name = ''

        num_iters = fdp.ConsumeIntInRange(1, 6)
        for _ in range(num_iters):
            if fdp.remaining_bytes() == 0:
                break
            target = fdp.ConsumeIntInRange(0, 25)
            try:
                if target == 0:
                    n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 10000)) if fdp.remaining_bytes() > 0 else 0
                    if n > 0:
                        s = fdp.ConsumeBytes(n).decode('latin-1')
                        conn.execute(s)
                elif target == 1:
                    n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 10000)) if fdp.remaining_bytes() > 0 else 0
                    if n > 0:
                        s = fdp.ConsumeBytes(n).decode('latin-1')
                        conn.executescript(s if s else 'SELECT 1;')
                elif target == 2:
                    n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 10000)) if fdp.remaining_bytes() > 0 else 0
                    if n > 0:
                        s = fdp.ConsumeBytes(n).decode('latin-1')
                        sqlite3.complete_statement(s if s else 'SELECT 1;')
                elif target == 3:
                    conn.execute('CREATE TABLE t(a TEXT)')
                elif target == 4:
                    conn.execute('CREATE TABLE t(a BLOB)')
                elif target == 5:
                    conn.execute('CREATE TABLE t(v INTEGER)')
                elif target == 6:
                    conn.execute('CREATE TABLE t(a TEXT, b BLOB)')
                elif target == 7:
                    conn.execute('CREATE TABLE t(a TEXT, b INTEGER)')
                elif target == 8:
                    n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 10000)) if fdp.remaining_bytes() > 0 else 0
                    if n > 0:
                        s = fdp.ConsumeBytes(n).decode('latin-1')
                        conn.execute('INSERT INTO t VALUES(?)', (s,))
                elif target == 9:
                    n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 10000)) if fdp.remaining_bytes() > 0 else 0
                    if n > 0:
                        s = fdp.ConsumeBytes(n).decode('latin-1')
                        data = s.encode('utf-8', 'replace')
                        conn.execute('INSERT INTO t VALUES(?, ?)', (s, data))
                elif target == 10:
                    n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 10000)) if fdp.remaining_bytes() > 0 else 0
                    if n > 0:
                        s = fdp.ConsumeBytes(n).decode('latin-1')
                        obj = _AdaptMe(s)
                        conn.execute('INSERT INTO t VALUES(?)', (obj,))
                elif target == 11:
                    n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 10000)) if fdp.remaining_bytes() > 0 else 0
                    data = fdp.ConsumeBytes(n)
                    limit = fdp.ConsumeIntInRange(0, min(len(data), 10000))
                    rows = [(data[i],) for i in range(limit)]
                    conn.executemany('INSERT INTO t VALUES(?)', rows)
                elif target == 12:
                    cur = conn.execute('SELECT * FROM t')
                    cur.fetchall()
                elif target == 13:
                    n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 10000)) if fdp.remaining_bytes() > 0 else 0
                    if n > 0:
                        s = fdp.ConsumeBytes(n).decode('latin-1')
                        conn.execute('SELECT * FROM t WHERE a LIKE ?', (s,))
                elif target == 14:
                    cur = conn.execute('SELECT count(*), sum(v), avg(v), min(v), max(v) FROM t')
                    cur.fetchone()
                elif target == 15:
                    if collation_name:
                        sql = 'SELECT * FROM t ORDER BY a COLLATE "{}"'.format(
                            collation_name.replace('"', '""'))
                        cur = conn.execute(sql)
                        cur.fetchall()
                elif target == 16:
                    if func_name:
                        sql = 'SELECT "{}"(a) FROM t'.format(func_name.replace('"', '""'))
                        cur = conn.execute(sql)
                        cur.fetchall()
                elif target == 17:
                    if agg_name:
                        sql = 'SELECT "{}"(v) FROM t'.format(agg_name.replace('"', '""'))
                        cur = conn.execute(sql)
                        cur.fetchone()
                elif target == 18:
                    n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 100)) if fdp.remaining_bytes() > 0 else 0
                    if n > 0:
                        name = fdp.ConsumeBytes(n).decode('latin-1')
                        narg = fdp.ConsumeIntInRange(-1, 8)
                        conn.create_function(name, narg, _identity_fn)
                        func_name = name
                elif target == 19:
                    n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 100)) if fdp.remaining_bytes() > 0 else 0
                    if n > 0:
                        name = fdp.ConsumeBytes(n).decode('latin-1')
                        narg = fdp.ConsumeIntInRange(-1, 8)
                        conn.create_aggregate(name, narg, _Agg)
                        agg_name = name
                elif target == 20:
                    conn.set_authorizer(_auth_fn)
                elif target == 21:
                    n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 100)) if fdp.remaining_bytes() > 0 else 0
                    if n > 0:
                        name = fdp.ConsumeBytes(n).decode('latin-1')
                        conn.create_collation(name, _collation_fn)
                        collation_name = name
                elif target == 22:
                    conn.row_factory = sqlite3.Row
                elif target == 23:
                    sqlite3.register_adapter(_AdaptMe, _adapter_fn)
                elif target == 24:
                    cur = conn.execute('SELECT rowid FROM t LIMIT 1')
                    row = cur.fetchone()
                    if row:
                        rid = row[0]
                        blob = conn.blobopen('main', 't', 'a', rid)
                        if fdp.ConsumeBool():
                            blob.read()
                        else:
                            n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 100))
                            blob.write(fdp.ConsumeBytes(n))
                        blob.close()
                elif target == 25:
                    # Guaranteed blob sequence: create table, insert, blobopen, read/write
                    conn.execute('CREATE TABLE IF NOT EXISTS blobt(data BLOB)')
                    n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 200)) if fdp.remaining_bytes() > 0 else 1
                    blob_data = fdp.ConsumeBytes(n) or b'\x00'
                    conn.execute('INSERT INTO blobt VALUES(?)', (blob_data,))
                    cur = conn.execute('SELECT rowid FROM blobt ORDER BY rowid DESC LIMIT 1')
                    row = cur.fetchone()
                    if row:
                        blob = conn.blobopen('main', 'blobt', 'data', row[0])
                        blob.read()
                        blob.seek(0)
                        write_data = fdp.ConsumeBytes(min(fdp.remaining_bytes(), len(blob_data)))
                        if write_data:
                            blob.write(write_data)
                        blob.seek(0)
                        blob.read()
                        _ = len(blob)
                        blob.close()
            except Exception:
                pass

        conn.close()
    except Exception:
        pass
