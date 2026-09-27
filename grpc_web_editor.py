# -*- coding: utf-8 -*-
# =============================================================================
#  gRPC-Web Protobuf Editor  -  Burp Suite (Jython) extension
# =============================================================================
#  Adds a "gRPC-Web" message editor tab to Proxy / Repeater / Intruder etc.
#  It transparently DECODES  Content-Type: application/grpc-web+proto  and
#  application/grpc-web-text bodies into an editable, schema-less protobuf
#  text tree, and RE-ENCODES your edits back to a valid gRPC-Web frame with a
#  corrected Content-Length. No .proto schema required.
#
#  Author : built for AppSec testing
#  Runtime: Jython 2.7 standalone jar (configure in Burp -> Extensions -> Options)
#  Load   : Burp -> Extensions -> Add -> Extension type: Python -> select this file
# =============================================================================

from burp import IBurpExtender, IMessageEditorTabFactory, IMessageEditorTab
from javax.swing import JPanel, JScrollPane, JTextArea, JLabel, BorderFactory
from java.awt import BorderLayout, Font
import struct
import base64

EXT_NAME = "gRPC-Web Protobuf Editor"

# Content-Type markers we handle
CT_PROTO = "application/grpc-web+proto"
CT_TEXT  = "application/grpc-web-text"
CT_TEXT2 = "application/grpc-web+text"
CT_GRPC  = "application/grpc"           # some gateways use bare grpc over h2c/proxied


# =============================================================================
#  --------------------------  CODEC (schema-less)  --------------------------
# =============================================================================
# Wire types: 0 varint | 1 64-bit | 2 length-delimited | 5 32-bit

def read_varint(buf, pos):
    result = 0
    shift = 0
    while True:
        if pos >= len(buf):
            raise ValueError("truncated varint")
        b = buf[pos]
        if not isinstance(b, int):
            b = ord(b)
        result |= (b & 0x7F) << shift
        pos += 1
        if not (b & 0x80):
            break
        shift += 7
        if shift > 70:
            raise ValueError("varint too long")
    return result, pos


def write_varint(value):
    out = bytearray()
    value = value & 0xFFFFFFFFFFFFFFFF
    while True:
        towrite = value & 0x7F
        value >>= 7
        if value:
            out.append(towrite | 0x80)
        else:
            out.append(towrite)
            break
    return out


def _b(buf):
    """Normalize any input to a bytearray.

    Handles: bytearray, bytes, py2 str, and Jython Java byte[] / jarray /
    lists of ints. Java bytes are signed (-128..127) so we mask to 0..255.
    """
    if isinstance(buf, bytearray):
        return buf
    if isinstance(buf, bytes):
        return bytearray(buf)
    out = bytearray()
    for c in buf:
        if isinstance(c, int):
            out.append(c & 0xFF)          # Jython Java byte / int list
        else:
            out.append(ord(c) & 0xFF)     # py2 str / char
    return out


def _looks_like_message(buf):
    try:
        fields = _decode_message(buf, depth=0, probe=True)
        return fields is not None and len(fields) > 0
    except Exception:
        return False


def _is_printable(buf):
    if len(buf) == 0:
        return False
    for c in buf:
        if not isinstance(c, int):
            c = ord(c)
        if c == 9 or c == 10 or c == 13 or (32 <= c <= 126):
            continue
        elif c >= 128:
            continue
        else:
            return False
    return True


def _decode_message(buf, depth, probe=False):
    buf = _b(buf)
    pos = 0
    fields = []
    n = len(buf)
    while pos < n:
        tag, pos = read_varint(buf, pos)
        field_no = tag >> 3
        wtype = tag & 0x07
        if field_no == 0:
            raise ValueError("field number 0")
        if wtype == 0:
            val, pos = read_varint(buf, pos)
            fields.append({"no": field_no, "type": "varint", "val": val})
        elif wtype == 1:
            if pos + 8 > n:
                raise ValueError("truncated fixed64")
            raw = bytes(buf[pos:pos + 8]); pos += 8
            fields.append({"no": field_no, "type": "fixed64", "val": raw})
        elif wtype == 5:
            if pos + 4 > n:
                raise ValueError("truncated fixed32")
            raw = bytes(buf[pos:pos + 4]); pos += 4
            fields.append({"no": field_no, "type": "fixed32", "val": raw})
        elif wtype == 2:
            length, pos = read_varint(buf, pos)
            if pos + length > n:
                raise ValueError("truncated length-delimited")
            raw = bytes(buf[pos:pos + length]); pos += length
            if probe:
                fields.append({"no": field_no, "type": "bytes", "val": raw})
            else:
                if length > 0 and _looks_like_message(raw) and depth < 20:
                    sub = _decode_message(raw, depth + 1)
                    fields.append({"no": field_no, "type": "message", "val": sub})
                elif _is_printable(raw):
                    fields.append({"no": field_no, "type": "string", "val": raw})
                else:
                    fields.append({"no": field_no, "type": "bytes", "val": raw})
        else:
            raise ValueError("unknown wire type %d" % wtype)
    return fields


def _encode_message(fields):
    out = bytearray()
    for f in fields:
        no = f["no"]; t = f["type"]
        if t == "varint":
            out += write_varint((no << 3) | 0); out += write_varint(int(f["val"]))
        elif t == "fixed64":
            out += write_varint((no << 3) | 1); out += _b(f["val"])
        elif t == "fixed32":
            out += write_varint((no << 3) | 5); out += _b(f["val"])
        elif t == "string":
            data = f["val"]
            if not isinstance(data, (bytes, bytearray)):
                data = data.encode("utf-8")
            out += write_varint((no << 3) | 2); out += write_varint(len(data)); out += _b(data)
        elif t == "bytes":
            data = _b(f["val"])
            out += write_varint((no << 3) | 2); out += write_varint(len(data)); out += data
        elif t == "message":
            sub = _encode_message(f["val"])
            out += write_varint((no << 3) | 2); out += write_varint(len(sub)); out += sub
        else:
            raise ValueError("unknown field type %s" % t)
    return out


def _hex(raw):
    return "0x" + "".join("%02x" % (c if isinstance(c, int) else ord(c)) for c in raw)


def _from_hex(s):
    s = s.strip()
    if s[:2] in ("0x", "0X"):
        s = s[2:]
    s = s.replace(" ", "").replace("\n", "").replace("\t", "")
    if len(s) % 2 != 0:
        raise ValueError("odd hex length")
    return bytearray(int(s[i:i + 2], 16) for i in range(0, len(s), 2))


def _escape_str(raw):
    if isinstance(raw, (bytes, bytearray)):
        try:
            s = bytes(raw).decode("utf-8")
        except Exception:
            s = "".join(chr(c if isinstance(c, int) else ord(c)) for c in raw)
    else:
        s = raw
    out = []
    for ch in s:
        if ch == "\\": out.append("\\\\")
        elif ch == '"': out.append('\\"')
        elif ch == "\n": out.append("\\n")
        elif ch == "\r": out.append("\\r")
        elif ch == "\t": out.append("\\t")
        else: out.append(ch)
    return "".join(out)


def _unescape_str(s):
    out = []; i = 0
    while i < len(s):
        ch = s[i]
        if ch == "\\" and i + 1 < len(s):
            nx = s[i + 1]
            mp = {"\\": "\\", '"': '"', "n": "\n", "r": "\r", "t": "\t"}
            out.append(mp.get(nx, nx)); i += 2
        else:
            out.append(ch); i += 1
    return "".join(out).encode("utf-8")


def _fixed_hint(raw, size):
    raw = bytes(raw); hints = []
    try:
        if size == 4:
            hints.append("i32=%d" % struct.unpack("<i", raw)[0])
            hints.append("f32=%g" % struct.unpack("<f", raw)[0])
        else:
            hints.append("i64=%d" % struct.unpack("<q", raw)[0])
            hints.append("f64=%g" % struct.unpack("<d", raw)[0])
    except Exception:
        pass
    return ", ".join(hints)


def fields_to_text(fields, indent=0):
    lines = []; pad = "  " * indent
    for f in fields:
        no = f["no"]; t = f["type"]
        if t == "varint":
            lines.append("%s%d varint: %d" % (pad, no, f["val"]))
        elif t == "fixed64":
            lines.append("%s%d fixed64: %s  # %s" % (pad, no, _hex(f["val"]), _fixed_hint(f["val"], 8)))
        elif t == "fixed32":
            lines.append("%s%d fixed32: %s  # %s" % (pad, no, _hex(f["val"]), _fixed_hint(f["val"], 4)))
        elif t == "string":
            lines.append('%s%d string: "%s"' % (pad, no, _escape_str(f["val"])))
        elif t == "bytes":
            lines.append("%s%d bytes: %s" % (pad, no, _hex(f["val"])))
        elif t == "message":
            lines.append("%s%d message:" % (pad, no))
            lines.extend(fields_to_text(f["val"], indent + 1))
    return lines


def _indent_of(line):
    n = 0
    for ch in line:
        if ch == " ": n += 1
        else: break
    return n // 2


def text_to_fields(lines, idx=0, cur_indent=0):
    fields = []
    while idx < len(lines):
        raw_line = lines[idx]
        if raw_line.strip() == "":
            idx += 1; continue
        ind = _indent_of(raw_line)
        if ind < cur_indent: break
        if ind > cur_indent: break
        line = raw_line.strip()
        head, _, rest = line.partition(":")
        head = head.strip(); parts = head.split()
        if len(parts) < 2:
            raise ValueError("cannot parse line: %r" % raw_line)
        no = int(parts[0]); t = parts[1]; rest = rest.strip()
        if t == "varint":
            fields.append({"no": no, "type": "varint", "val": int(rest.split("#")[0].strip())}); idx += 1
        elif t == "fixed64":
            fields.append({"no": no, "type": "fixed64", "val": _from_hex(rest.split("#")[0].strip())}); idx += 1
        elif t == "fixed32":
            fields.append({"no": no, "type": "fixed32", "val": _from_hex(rest.split("#")[0].strip())}); idx += 1
        elif t == "string":
            s = rest
            if s.startswith('"'):
                s = s[1:]
                if s.endswith('"'):
                    s = s[:-1]
            fields.append({"no": no, "type": "string", "val": _unescape_str(s)}); idx += 1
        elif t == "bytes":
            fields.append({"no": no, "type": "bytes", "val": _from_hex(rest.split("#")[0].strip())}); idx += 1
        elif t == "message":
            sub, idx = text_to_fields(lines, idx + 1, cur_indent + 1)
            fields.append({"no": no, "type": "message", "val": sub})
        else:
            raise ValueError("unknown type in line: %r" % raw_line)
    return fields, idx


def parse_grpc_web_frames(data):
    data = _b(data); frames = []; pos = 0; n = len(data)
    while pos + 5 <= n:
        flag = data[pos]
        length = struct.unpack(">I", bytes(data[pos + 1:pos + 5]))[0]
        pos += 5
        payload = bytes(data[pos:pos + length]); pos += length
        frames.append((flag, payload))
        if pos > n:
            break
    return frames


def build_grpc_web_frames(frames):
    out = bytearray()
    for flag, payload in frames:
        out.append(flag & 0xFF)
        out += struct.pack(">I", len(payload))
        out += _b(payload)
    return out


def decode_body_to_text(body, is_text_transport):
    body = _b(body)
    if is_text_transport:
        try:
            body = bytearray(base64.b64decode(bytes(body)))
        except Exception:
            pass
    frames = parse_grpc_web_frames(body)
    if not frames:
        return "# No gRPC-Web frames found (body may be empty or not framed).\n"
    out_lines = []
    for i, (flag, payload) in enumerate(frames):
        is_trailer = bool(flag & 0x80)
        out_lines.append("=== Frame %d (flag=0x%02x%s) ===" % (i, flag, ", TRAILER" if is_trailer else ""))
        if is_trailer:
            try:
                readable = bytes(payload).decode("utf-8", "replace")
                for rl in readable.split("\r\n"):
                    out_lines.append("# " + rl)
            except Exception:
                pass
            out_lines.append("trailer-bytes: %s" % _hex(payload))
        else:
            try:
                fields = _decode_message(payload, depth=0)
                out_lines.extend(fields_to_text(fields))
            except Exception as e:
                out_lines.append("# decode failed: %s" % e)
                out_lines.append("raw-bytes: %s" % _hex(payload))
        out_lines.append("")
    return "\n".join(out_lines)


def encode_text_to_body(text, is_text_transport):
    lines = text.split("\n")
    frames = []; i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("=== Frame"):
            is_trailer = "TRAILER" in line
            flag = 0x00
            try:
                fpos = line.find("flag=0x")
                flag = int(line[fpos + 7:fpos + 9], 16)
            except Exception:
                flag = 0x80 if is_trailer else 0x00
            j = i + 1; body_lines = []
            while j < len(lines) and not lines[j].startswith("=== Frame"):
                body_lines.append(lines[j]); j += 1
            if is_trailer:
                payload = b""
                for bl in body_lines:
                    s = bl.strip()
                    if s.startswith("trailer-bytes:"):
                        payload = bytes(_from_hex(s.split(":", 1)[1])); break
                frames.append((flag, payload))
            else:
                # raw-bytes fallback (undecodable frame) round-trips verbatim
                raw_line = None
                for bl in body_lines:
                    if bl.strip().startswith("raw-bytes:"):
                        raw_line = bl.strip(); break
                if raw_line is not None:
                    payload = bytes(_from_hex(raw_line.split(":", 1)[1]))
                else:
                    content = [bl for bl in body_lines if not bl.strip().startswith("#")]
                    fields, _ = text_to_fields(content, 0, 0)
                    payload = bytes(_encode_message(fields))
                frames.append((flag, payload))
            i = j
        else:
            i += 1
    raw = build_grpc_web_frames(frames)
    if is_text_transport:
        raw = bytearray(base64.b64encode(bytes(raw)))
    return bytes(raw)


# =============================================================================
#  --------------------------  BURP INTEGRATION  ----------------------------
# =============================================================================

class BurpExtender(IBurpExtender, IMessageEditorTabFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName(EXT_NAME)
        callbacks.registerMessageEditorTabFactory(self)
        callbacks.printOutput(EXT_NAME + " loaded. Tab 'gRPC-Web' appears on "
                              "grpc-web+proto / grpc-web-text messages.")

    def createNewInstance(self, controller, editable):
        return GrpcWebTab(self, controller, editable)


class GrpcWebTab(IMessageEditorTab):

    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._helpers = extender._helpers
        self._callbacks = extender._callbacks
        self._editable = editable
        self._controller = controller

        self._current = None            # full original message bytes
        self._is_request = True
        self._is_text_transport = False
        self._body_offset = 0

        self._panel = JPanel(BorderLayout())
        info = JLabel(" gRPC-Web Protobuf (schema-less). Edit values, then switch "
                      "tab / send \u2014 body & Content-Length are rebuilt automatically.")
        info.setBorder(BorderFactory.createEmptyBorder(4, 6, 4, 6))
        self._panel.add(info, BorderLayout.NORTH)

        self._txt = JTextArea()
        self._txt.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._txt.setEditable(editable)
        self._panel.add(JScrollPane(self._txt), BorderLayout.CENTER)

    # ---- IMessageEditorTab ------------------------------------------------
    def getTabCaption(self):
        return "gRPC-Web"

    def getUiComponent(self):
        return self._panel

    def _content_type(self, content, is_request):
        try:
            if is_request:
                info = self._helpers.analyzeRequest(content)
            else:
                info = self._helpers.analyzeResponse(content)
            for h in info.getHeaders():
                hl = h.lower()
                if hl.startswith("content-type:"):
                    return hl.split(":", 1)[1].strip()
        except Exception:
            pass
        return ""

    def isEnabled(self, content, isRequest):
        if content is None:
            return False
        ct = self._content_type(content, isRequest)
        return (CT_PROTO in ct) or (CT_TEXT in ct) or (CT_TEXT2 in ct) or \
               (ct.strip() == CT_GRPC) or ct.startswith(CT_GRPC + ";") or (CT_GRPC + "+" in ct)

    def setMessage(self, content, isRequest):
        if content is None:
            self._txt.setText("")
            self._current = None
            return
        self._current = content
        self._is_request = isRequest
        ct = self._content_type(content, isRequest)
        self._is_text_transport = (CT_TEXT in ct) or (CT_TEXT2 in ct)

        if isRequest:
            info = self._helpers.analyzeRequest(content)
        else:
            info = self._helpers.analyzeResponse(content)
        self._body_offset = info.getBodyOffset()
        body = content[self._body_offset:]
        try:
            text = decode_body_to_text(body, self._is_text_transport)
        except Exception as e:
            text = "# Failed to decode body: %s\n" % e
        self._txt.setText(text)
        self._txt.setCaretPosition(0)

    def getMessage(self):
        if self._current is None:
            return self._current
        if not self.isModified():
            return self._current
        try:
            new_body = encode_text_to_body(self._txt.getText(), self._is_text_transport)
        except Exception as e:
            self._callbacks.printError("gRPC-Web encode error: %s" % e)
            return self._current  # keep original on parse failure

        if self._is_request:
            info = self._helpers.analyzeRequest(self._current)
            header_list = info.getHeaders()
        else:
            info = self._helpers.analyzeResponse(self._current)
            header_list = info.getHeaders()
        # buildHttpMessage recalculates Content-Length automatically
        return self._helpers.buildHttpMessage(header_list, new_body)

    def isModified(self):
        return self._txt.getText() is not None and self._editable

    def getSelectedData(self):
        sel = self._txt.getSelectedText()
        if sel is None:
            return None
        return self._helpers.stringToBytes(sel)
