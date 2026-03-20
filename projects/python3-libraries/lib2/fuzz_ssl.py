from fuzz_dp import FuzzedDataProvider
import os
import ssl
import tempfile

def FuzzerRunOne(FuzzerInput):
    if len(FuzzerInput) < 1 or len(FuzzerInput) > 0x100000:
        return
    fdp = FuzzedDataProvider(FuzzerInput)
    target = fdp.ConsumeIntInRange(0, 1)
    data = fdp.ConsumeBytes(fdp.remaining_bytes())
    try:
        if target == 0:
            ssl.DER_cert_to_PEM_cert(data)
        else:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            with tempfile.NamedTemporaryFile(suffix='.pem', delete=False) as tmp:
                tmpname = tmp.name
                tmp.write(data)
                tmp.flush()
            try:
                ctx.load_verify_locations(tmpname)
            finally:
                os.unlink(tmpname)
    except Exception:
        pass
