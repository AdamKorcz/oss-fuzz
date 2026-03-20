from fuzz_dp import FuzzedDataProvider
import os
import io
import tempfile

def op_bytesio(fdp):
    trunc_pos = fdp.ConsumeIntInRange(0, fdp.remaining_bytes())
    data = fdp.ConsumeBytes(fdp.remaining_bytes())
    bio = io.BytesIO()
    bio.write(data)
    bio.seek(0)
    bio.read()
    bio.seek(0)
    bio.readline()
    buf = bytearray(min(len(data), 100))
    bio.seek(0)
    bio.readinto(buf)
    bio.getbuffer()
    bio.truncate(trunc_pos)
    bio.getvalue()

def op_textiowrapper(fdp):
    encodings = ['utf-8', 'latin-1', 'ascii', 'utf-16']
    encoding = fdp.PickValueInList(encodings)
    newlines = [None, '', '\n', '\r', '\r\n']
    newline = fdp.PickValueInList(newlines)
    data = fdp.ConsumeBytes(fdp.remaining_bytes())
    bio = io.BytesIO(data)
    wrapper = io.TextIOWrapper(bio, encoding=encoding, errors='replace', newline=newline)
    wrapper.read()
    wrapper.seek(0)
    wrapper.readline()
    wrapper.detach()

def op_buffered_io(fdp):
    target = fdp.ConsumeIntInRange(0, 2)
    read_size = fdp.ConsumeIntInRange(0, fdp.remaining_bytes())
    write_size = fdp.ConsumeIntInRange(0, fdp.remaining_bytes())
    data = fdp.ConsumeBytes(fdp.remaining_bytes())
    if target == 0:
        raw = io.BytesIO(data)
        br = io.BufferedReader(raw)
        br.read()
    elif target == 1:
        raw = io.BytesIO()
        bw = io.BufferedWriter(raw)
        bw.write(data)
        bw.flush()
    else:
        raw = io.BytesIO(data)
        brw = io.BufferedRandom(raw)
        brw.read(read_size)
        brw.write(data[:write_size])
        brw.seek(0)
        brw.read()

def op_fileio(fdp):
    do_write = fdp.ConsumeBool()
    data = fdp.ConsumeBytes(fdp.remaining_bytes())
    tmpname = None
    try:
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmpname = tmp.name
            if do_write:
                f = io.FileIO(tmpname, 'w')
                f.write(data)
                f.close()
                f = io.FileIO(tmpname, 'r')
                f.read()
                f.close()
            else:
                tmp.write(data)
                tmp.flush()
                f = io.FileIO(tmpname, 'r')
                f.read()
                f.close()
    finally:
        if tmpname:
            try:
                os.unlink(tmpname)
            except Exception:
                pass

def op_io_open(fdp):
    modes = ['rb', 'r', 'rb']
    mode = fdp.PickValueInList(modes)
    data = fdp.ConsumeBytes(fdp.remaining_bytes())
    tmpname = None
    try:
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmpname = tmp.name
            tmp.write(data)
            tmp.flush()
        with io.open(tmpname, mode, errors='replace' if 'b' not in mode else None) as f:
            f.read()
    finally:
        if tmpname:
            try:
                os.unlink(tmpname)
            except Exception:
                pass

def op_newline_decoder(fdp):
    translate = fdp.ConsumeBool()
    n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 10000)) if fdp.remaining_bytes() > 0 else 0
    if n == 0:
        return
    s = fdp.ConsumeBytes(n).decode('latin-1')
    decoder = io.IncrementalNewlineDecoder(None, translate)
    decoder.decode(s)
    decoder.getstate()
    decoder.reset()

def op_stringio(fdp):
    n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 10000)) if fdp.remaining_bytes() > 0 else 0
    if n == 0:
        return
    s = fdp.ConsumeBytes(n).decode('latin-1')
    sio = io.StringIO(s)
    sio.read()
    sio.seek(0)
    sio.readline()
    sio.seek(0)
    sio.write(s)
    sio.getvalue()

def FuzzerRunOne(FuzzerInput):
    if len(FuzzerInput) < 1 or len(FuzzerInput) > 0x100000:
        return
    fdp = FuzzedDataProvider(FuzzerInput)
    op = fdp.ConsumeIntInRange(0, 6)
    try:
        if op == 0:
            op_bytesio(fdp)
        elif op == 1:
            op_textiowrapper(fdp)
        elif op == 2:
            op_buffered_io(fdp)
        elif op == 3:
            op_fileio(fdp)
        elif op == 4:
            op_io_open(fdp)
        elif op == 5:
            op_newline_decoder(fdp)
        else:
            op_stringio(fdp)
    except Exception:
        pass
