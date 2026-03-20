from fuzz_dp import FuzzedDataProvider
import csv
import io

def op_sniffer(fdp):
    n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 10000)) if fdp.remaining_bytes() > 0 else 0
    if n == 0:
        return
    s = fdp.ConsumeBytes(n).decode('latin-1')
    sniffer = csv.Sniffer()
    use_has_header = fdp.ConsumeBool()
    if use_has_header:
        sniffer.has_header(s)
    else:
        sniffer.sniff(s)

def op_writer(fdp):
    quoting_modes = [csv.QUOTE_MINIMAL, csv.QUOTE_ALL, csv.QUOTE_NONNUMERIC, csv.QUOTE_NONE]
    quoting = fdp.PickValueInList(quoting_modes)
    use_dict = fdp.ConsumeBool()
    n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 10000)) if fdp.remaining_bytes() > 0 else 0
    if n == 0:
        return
    s = fdp.ConsumeBytes(n).decode('latin-1')
    lines = s.splitlines()

    out = io.StringIO()
    if use_dict and lines:
        headers = lines[0].split(',')[:10]
        if not headers:
            headers = ['a']
        writer = csv.DictWriter(out, fieldnames=headers, quoting=quoting,
                                escapechar='\\' if quoting == csv.QUOTE_NONE else None)
        writer.writeheader()
        for line in lines[1:]:
            vals = line.split(',')
            row = {h: vals[i] if i < len(vals) else '' for i, h in enumerate(headers)}
            writer.writerow(row)
    else:
        writer = csv.writer(out, quoting=quoting,
                           escapechar='\\' if quoting == csv.QUOTE_NONE else None)
        for line in lines:
            writer.writerow(line.split(','))
    out.getvalue()

def op_reader(fdp):
    delimiters = [',', '\t', ';', '|', ':']
    delimiter = fdp.PickValueInList(delimiters)
    quoting_modes = [csv.QUOTE_MINIMAL, csv.QUOTE_ALL, csv.QUOTE_NONNUMERIC, csv.QUOTE_NONE]
    quoting = fdp.PickValueInList(quoting_modes)
    n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 10000)) if fdp.remaining_bytes() > 0 else 0
    if n == 0:
        return
    s = fdp.ConsumeBytes(n).decode('latin-1')
    reader = csv.reader(s.splitlines(), delimiter=delimiter, quoting=quoting,
                        escapechar='\\' if quoting == csv.QUOTE_NONE else None)
    for row in reader:
        pass

def op_roundtrip(fdp):
    n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 10000)) if fdp.remaining_bytes() > 0 else 0
    if n == 0:
        return
    s = fdp.ConsumeBytes(n).decode('latin-1')
    lines = s.splitlines()
    out = io.StringIO()
    writer = csv.writer(out)
    for line in lines:
        writer.writerow(line.split(','))
    written = out.getvalue()
    reader = csv.reader(written.splitlines())
    for row in reader:
        pass

def FuzzerRunOne(FuzzerInput):
    if len(FuzzerInput) < 1 or len(FuzzerInput) > 0x10000:
        return
    fdp = FuzzedDataProvider(FuzzerInput)
    op = fdp.ConsumeIntInRange(0, 3)
    try:
        if op == 0:
            op_sniffer(fdp)
        elif op == 1:
            op_writer(fdp)
        elif op == 2:
            op_reader(fdp)
        else:
            op_roundtrip(fdp)
    except Exception:
        pass
