# Annotated Wire Hex Dump — BHTTP Protocol Exchange

This document provides a byte-by-byte annotated walkthrough of a real network exchange captured directly between the `bcurl` client and the `bserve` server over a TCP connection.

---

## 1. Request Frame (`examples/request.hex`)

A client transmits a BHTTP `REQUEST` frame to fetch `/index.html` with headers `host: localhost:64769` and `accept: text/html`, requesting connection closure (`CONN_CLOSE`).

### 1.1 Complete Wire Hex Dump

```text
00000000  B7 48 01 01 01 00 00 00 00 00 00 2F 01 00 0B 2F   |.H........./.../|
00000010  69 6E 64 65 78 2E 68 74 6D 6C 02 00 03 00 0F 6C   |index.html.....l|
00000020  6F 63 61 6C 68 6F 73 74 3A 36 34 37 36 39 00 04   |ocalhost:64769..|
00000030  00 09 74 65 78 74 2F 68 74 6D 6C                  |..text/html|
```

Total size: **59 bytes** (12 bytes fixed header + 47 bytes payload).

---

### 1.2 Byte-by-Byte Structural Breakdown

#### Fixed Frame Header (12 bytes, offsets 0x0000 – 0x000B)

| Byte Offset (Hex) | Length | Wire Bytes | Field Name | SPEC § | Value / Meaning |
|---|---|---|---|---|---|
| `0x0000 – 0x0001` | 2 | `B7 48` | Magic | §5 | Protocol discriminator (`0xB748`) |
| `0x0002` | 1 | `01` | Version | §5 | Protocol Version 1 |
| `0x0003` | 1 | `01` | Frame Type | §6 | `0x01` = `FRAME_REQUEST` |
| `0x0004` | 1 | `01` | Flags | §7 | `0x01` (`CONN_CLOSE` bit 0 set) |
| `0x0005` | 1 | `00` | Reserved | §5 | `0x00` (sender transmits 0) |
| `0x0006 – 0x0007` | 2 | `00 00` | Status Code | §5, §8 | `0x0000` (REQUEST status MUST be zero) |
| `0x0008 – 0x000B` | 4 | `00 00 00 2F` | Payload Length | §5 | uint32 BE: `47` bytes following header |

#### Request Payload (47 bytes, offsets 0x000C – 0x003A)

| Byte Offset (Hex) | Length | Wire Bytes | Field Name | SPEC § | Value / Meaning |
|---|---|---|---|---|---|
| `0x000C` | 1 | `01` | Method | §11 | `0x01` = `GET` |
| `0x000D – 0x000E` | 2 | `00 0B` | Path Length | §11 | uint16 BE: `11` bytes |
| `0x000F – 0x0019` | 11 | `2F 69 6E 64 65 78 2E 68 74 6D 6C` | Path | §11, §12 | UTF-8: `"/index.html"` |
| `0x001A` | 1 | `02` | Header Count | §11 | uint8: `2` headers present |

##### Header Entry 1: `host: localhost:64769`
| Byte Offset (Hex) | Length | Wire Bytes | Field Name | SPEC § | Value / Meaning |
|---|---|---|---|---|---|
| `0x001B` | 1 | `00` | Name Tag | §9.2 | `0x00` = Indexed Name |
| `0x001C` | 1 | `03` | Name ID | §9.1 | `0x03` = Static Table Index 3 (`"host"`) |
| `0x001D – 0x001E` | 2 | `00 0F` | Value Length | §9.2 | uint16 BE: `15` bytes |
| `0x001F – 0x002D` | 15 | `6C 6F 63 61 6C 68 6F 73 74 3A 36 34 37 36 39` | Value Bytes | §9.2 | UTF-8: `"localhost:64769"` |

##### Header Entry 2: `accept: text/html`
| Byte Offset (Hex) | Length | Wire Bytes | Field Name | SPEC § | Value / Meaning |
|---|---|---|---|---|---|
| `0x002E` | 1 | `00` | Name Tag | §9.2 | `0x00` = Indexed Name |
| `0x002F` | 1 | `04` | Name ID | §9.1 | `0x04` = Static Table Index 4 (`"accept"`) |
| `0x0030 – 0x0031` | 2 | `00 09` | Value Length | §9.2 | uint16 BE: `9` bytes |
| `0x0032 – 0x003A` | 9 | `74 65 78 74 2F 68 74 6D 6C` | Value Bytes | §9.2 | UTF-8: `"text/html"` |

**Verification of Payload Consistency (§11):**
`1 (method) + 2 (path_len) + 11 (path) + 1 (header_count) + 19 (header 1) + 13 (header 2) = 47 bytes`. Matches `payload_length = 47` exactly.

---

## 2. Response Frame (`examples/response.hex`)

The server replies with a BHTTP `RESPONSE` frame containing status `200 OK`, response headers, and the document body.

### 2.1 Wire Hex Dump (Header and Payload Prefix)

```text
00000000  B7 48 01 02 01 00 00 C8 00 00 02 E4 03 00 00 00   |.H..............|
00000010  09 74 65 78 74 2F 68 74 6D 6C 00 01 00 03 37 30   |.text/html....70|
00000020  31 00 05 00 0A 62 73 65 72 76 65 2F 31 2E 30 00   |1....bserve/1.0.|
00000030  00 02 BD 3C 21 44 4F 43 54 59 50 45 20 68 74 6D   |...<!DOCTYPE htm|
00000040  6C 3E 0A 3C 68 74 6D 6C 20 6C 61 6E 67 3D 22 65   |l>.<html lang="e|
...
```

Total size: **752 bytes** (12 bytes fixed header + 740 bytes payload).

---

### 2.2 Byte-by-Byte Structural Breakdown

#### Fixed Frame Header (12 bytes, offsets 0x0000 – 0x000B)

| Byte Offset (Hex) | Length | Wire Bytes | Field Name | SPEC § | Value / Meaning |
|---|---|---|---|---|---|
| `0x0000 – 0x0001` | 2 | `B7 48` | Magic | §5 | Protocol discriminator (`0xB748`) |
| `0x0002` | 1 | `01` | Version | §5 | Protocol Version 1 |
| `0x0003` | 1 | `02` | Frame Type | §6 | `0x02` = `FRAME_RESPONSE` |
| `0x0004` | 1 | `01` | Flags | §7 | `0x01` (`CONN_CLOSE` echoed back) |
| `0x0005` | 1 | `00` | Reserved | §5 | `0x00` (sender transmits 0) |
| `0x0006 – 0x0007` | 2 | `00 C8` | Status Code | §8 | uint16 BE: `0x00C8` = `200 OK` |
| `0x0008 – 0x000B` | 4 | `00 00 02 E4` | Payload Length | §5 | uint32 BE: `740` (`0x02E4`) bytes |

#### Response Payload (740 bytes, offsets 0x000C – 0x02EF)

| Byte Offset (Hex) | Length | Wire Bytes | Field Name | SPEC § | Value / Meaning |
|---|---|---|---|---|---|
| `0x000C` | 1 | `03` | Header Count | §13 | uint8: `3` headers |

##### Header Entry 1: `content-type: text/html`
| Byte Offset (Hex) | Length | Wire Bytes | Field Name | SPEC § | Value / Meaning |
|---|---|---|---|---|---|
| `0x000D` | 1 | `00` | Name Tag | §9.2 | `0x00` = Indexed Name |
| `0x000E` | 1 | `00` | Name ID | §9.1 | `0x00` = `"content-type"` |
| `0x000F – 0x0010` | 2 | `00 09` | Value Length | §9.2 | uint16 BE: `9` bytes |
| `0x0011 – 0x0019` | 9 | `74 65 78 74 2F 68 74 6D 6C` | Value Bytes | §9.2 | UTF-8: `"text/html"` |

##### Header Entry 2: `content-length: 701`
| Byte Offset (Hex) | Length | Wire Bytes | Field Name | SPEC § | Value / Meaning |
|---|---|---|---|---|---|
| `0x001A` | 1 | `00` | Name Tag | §9.2 | `0x00` = Indexed Name |
| `0x001B` | 1 | `01` | Name ID | §9.1 | `0x01` = `"content-length"` |
| `0x001C – 0x001D` | 2 | `00 03` | Value Length | §9.2 | uint16 BE: `3` bytes |
| `0x001E – 0x0020` | 3 | `37 30 31` | Value Bytes | §9.2 | UTF-8: `"701"` |

##### Header Entry 3: `server: bserve/1.0`
| Byte Offset (Hex) | Length | Wire Bytes | Field Name | SPEC § | Value / Meaning |
|---|---|---|---|---|---|
| `0x0021` | 1 | `00` | Name Tag | §9.2 | `0x00` = Indexed Name |
| `0x0022` | 1 | `05` | Name ID | §9.1 | `0x05` = `"server"` |
| `0x0023 – 0x0024` | 2 | `00 0A` | Value Length | §9.2 | uint16 BE: `10` bytes |
| `0x0025 – 0x002E` | 10 | `62 73 65 72 76 65 2F 31 2E 30` | Value Bytes | §9.2 | UTF-8: `"bserve/1.0"` |

##### Body Length and Content
| Byte Offset (Hex) | Length | Wire Bytes | Field Name | SPEC § | Value / Meaning |
|---|---|---|---|---|---|
| `0x002F – 0x0032` | 4 | `00 00 02 BD` | Body Length | §13 | uint32 BE: `701` (`0x02BD`) bytes |
| `0x0033 – 0x02EF` | 701 | `3C 21 44 4F 43 ...` | Body | §13 | Raw octets of `index.html` (701 bytes) |

**Verification of Payload Consistency (§13):**
`1 (header_count) + 13 (header 1) + 7 (header 2) + 14 (header 3) + 4 (body_len) + 701 (body) = 740 bytes`. Matches `payload_length = 740` exactly.
