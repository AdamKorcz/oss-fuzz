from fuzz_dp import FuzzedDataProvider
import xml.parsers.expat
import io

ENCODINGS = [None, 'utf-8', 'iso-8859-1']

def FuzzerRunOne(FuzzerInput):
    if len(FuzzerInput) < 1 or len(FuzzerInput) > 0x10000:
        return
    fdp = FuzzedDataProvider(FuzzerInput)
    use_parse_file = fdp.ConsumeBool()
    encoding = fdp.PickValueInList(ENCODINGS)
    try:
        p = xml.parsers.expat.ParserCreate(encoding)
        p.StartElementHandler = lambda name, attrs: None
        p.EndElementHandler = lambda name: None
        p.CharacterDataHandler = lambda data: None
        p.ProcessingInstructionHandler = lambda target, data: None
        p.CommentHandler = lambda data: None
        p.StartCdataSectionHandler = lambda: None
        p.EndCdataSectionHandler = lambda: None
        p.DefaultHandler = lambda data: None

        data = fdp.ConsumeBytes(fdp.remaining_bytes())
        if use_parse_file:
            p.ParseFile(io.BytesIO(data))
        else:
            p.Parse(data, True)
    except xml.parsers.expat.ExpatError:
        pass
    except Exception:
        pass
