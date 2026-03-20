from fuzz_dp import FuzzedDataProvider
import unicodedata

NORMALIZE_FORMS = ['NFC', 'NFD', 'NFKC', 'NFKD']

def FuzzerRunOne(FuzzerInput):
    if len(FuzzerInput) < 1 or len(FuzzerInput) > 0x10000:
        return
    fdp = FuzzedDataProvider(FuzzerInput)
    target = fdp.ConsumeIntInRange(0, 12)
    n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 10000)) if fdp.remaining_bytes() > 0 else 0
    if n == 0:
        return
    s = fdp.ConsumeUnicode(n)
    try:
        if target == 0:
            for ch in s[:100]:
                unicodedata.category(ch)
        elif target == 1:
            for ch in s[:100]:
                unicodedata.bidirectional(ch)
        elif target == 2:
            form = fdp.PickValueInList(NORMALIZE_FORMS)
            unicodedata.normalize(form, s)
        elif target == 3:
            for ch in s[:100]:
                try:
                    unicodedata.numeric(ch)
                except ValueError:
                    pass
        elif target == 4:
            for ch in s[:100]:
                try:
                    unicodedata.decimal(ch)
                except ValueError:
                    pass
        elif target == 5:
            for ch in s[:100]:
                unicodedata.combining(ch)
        elif target == 6:
            for ch in s[:100]:
                unicodedata.east_asian_width(ch)
        elif target == 7:
            for ch in s[:100]:
                unicodedata.mirrored(ch)
        elif target == 8:
            for ch in s[:100]:
                try:
                    unicodedata.name(ch)
                except ValueError:
                    pass
        elif target == 9:
            for ch in s[:100]:
                unicodedata.decomposition(ch)
        elif target == 10:
            try:
                unicodedata.lookup(s[:100])
            except KeyError:
                pass
        elif target == 11:
            for ch in s[:100]:
                try:
                    unicodedata.digit(ch)
                except ValueError:
                    pass
        elif target == 12:
            form = fdp.PickValueInList(NORMALIZE_FORMS)
            unicodedata.is_normalized(form, s)
    except Exception:
        pass
