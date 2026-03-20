from fuzz_dp import FuzzedDataProvider
from datetime import date, time, datetime, timedelta, timezone

STRPTIME_FORMATS = [
    "%Y-%m-%d", "%Y-%m-%d %H:%M:%S", "%d/%m/%Y", "%m/%d/%Y",
    "%Y%m%d", "%H:%M:%S", "%I:%M %p", "%Y-%m-%dT%H:%M:%S",
    "%a %b %d %H:%M:%S %Y", "%c",
]

def op_parse(fdp):
    n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 10000)) if fdp.remaining_bytes() > 0 else 0
    if n == 0:
        return
    s = fdp.ConsumeBytes(n).decode('latin-1')
    target = fdp.ConsumeIntInRange(0, 3)
    if target == 0:
        date.fromisoformat(s)
    elif target == 1:
        time.fromisoformat(s)
    elif target == 2:
        datetime.fromisoformat(s)
    else:
        fmt = fdp.PickValueInList(STRPTIME_FORMATS)
        datetime.strptime(s, fmt)

def op_format(fdp):
    n = fdp.ConsumeIntInRange(1, min(fdp.remaining_bytes(), 1000)) if fdp.remaining_bytes() > 0 else 0
    if n == 0:
        return
    fmt = fdp.ConsumeBytes(n).decode('latin-1')
    target = fdp.ConsumeIntInRange(0, 2)
    if target == 0:
        year = fdp.ConsumeIntInRange(1, 9999)
        month = fdp.ConsumeIntInRange(1, 12)
        day = fdp.ConsumeIntInRange(1, 28)
        date(year, month, day).strftime(fmt)
    elif target == 1:
        hour = fdp.ConsumeIntInRange(0, 23)
        minute = fdp.ConsumeIntInRange(0, 59)
        second = fdp.ConsumeIntInRange(0, 59)
        time(hour, minute, second).strftime(fmt)
    else:
        year = fdp.ConsumeIntInRange(1, 9999)
        month = fdp.ConsumeIntInRange(1, 12)
        day = fdp.ConsumeIntInRange(1, 28)
        hour = fdp.ConsumeIntInRange(0, 23)
        minute = fdp.ConsumeIntInRange(0, 59)
        second = fdp.ConsumeIntInRange(0, 59)
        datetime(year, month, day, hour, minute, second).strftime(fmt)

def op_timedelta(fdp):
    days = fdp.ConsumeIntInRange(-999999, 999999)
    seconds = fdp.ConsumeIntInRange(0, 86399)
    microseconds = fdp.ConsumeIntInRange(0, 999999)
    td1 = timedelta(days=days, seconds=seconds, microseconds=microseconds)
    td2 = timedelta(days=fdp.ConsumeIntInRange(-100, 100),
                    seconds=fdp.ConsumeIntInRange(0, 3600))
    _ = td1 + td2
    _ = td1 - td2
    _ = td1 * fdp.ConsumeIntInRange(-10, 10)
    _ = abs(td1)
    _ = str(td1)
    _ = repr(td1)
    _ = td1.total_seconds()
    if td2.total_seconds() != 0:
        _ = td1 // td2

def op_arithmetic(fdp):
    year = fdp.ConsumeIntInRange(1, 9999)
    month = fdp.ConsumeIntInRange(1, 12)
    day = fdp.ConsumeIntInRange(1, 28)
    d = date(year, month, day)
    td = timedelta(days=fdp.ConsumeIntInRange(-365, 365))
    _ = d + td
    _ = d - td
    d2 = date(fdp.ConsumeIntInRange(1, 9999), fdp.ConsumeIntInRange(1, 12),
              fdp.ConsumeIntInRange(1, 28))
    _ = d - d2
    _ = d < d2
    _ = d == d2
    _ = d.replace(year=fdp.ConsumeIntInRange(1, 9999))
    _ = d.toordinal()
    _ = d.weekday()
    _ = d.isoweekday()
    _ = d.isoformat()
    _ = d.timetuple()

def op_fromtimestamp(fdp):
    ts = fdp.ConsumeFloatInRange(-62135596800.0, 253402300799.0)
    _ = date.fromtimestamp(ts)
    _ = datetime.fromtimestamp(ts)
    ofs_hours = fdp.ConsumeIntInRange(-12, 14)
    tz = timezone(timedelta(hours=ofs_hours))
    _ = datetime.fromtimestamp(ts, tz=tz)

def FuzzerRunOne(FuzzerInput):
    if len(FuzzerInput) < 1 or len(FuzzerInput) > 0x10000:
        return
    fdp = FuzzedDataProvider(FuzzerInput)
    op = fdp.ConsumeIntInRange(0, 4)
    try:
        if op == 0:
            op_parse(fdp)
        elif op == 1:
            op_format(fdp)
        elif op == 2:
            op_timedelta(fdp)
        elif op == 3:
            op_arithmetic(fdp)
        else:
            op_fromtimestamp(fdp)
    except Exception:
        pass
