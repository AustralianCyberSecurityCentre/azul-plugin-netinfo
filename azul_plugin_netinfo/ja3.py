"""Scan a PCAP for ClientHello and extract JA3 hash.

Slight modification of https://github.com/salesforce/ja3/blob/master/python/ja3.py

Copyright (c) 2017, Salesforce.com, Inc.
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.

* Neither the name of Salesforce.com nor the names of its contributors may be
used to endorse or promote products derived from this software without specific
prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
THE POSSIBILITY OF SUCH DAMAGE.
"""

import binascii
import io
import socket
import struct
from hashlib import md5

import dpkt

GREASE_TABLE = {
    0x0A0A,
    0x1A1A,
    0x2A2A,
    0x3A3A,
    0x4A4A,
    0x5A5A,
    0x6A6A,
    0x7A7A,
    0x8A8A,
    0x9A9A,
    0xAAAA,
    0xBABA,
    0xCACA,
    0xDADA,
    0xEAEA,
    0xFAFA,
}
# GREASE_TABLE Ref: https://tools.ietf.org/html/draft-davidben-tls-grease-00
TLS_HANDSHAKE = 0x16
TLS_VERSION_MAJOR = 0x03
# NOTE: dpkt can only handle SSL3.0, TLS1.0, 1.1 and 1.2, but we'll leave 1.3
TLS_VERSION_MINORS = (0x00, 0x01, 0x02, 0x03, 0x04)


def convert_ip(value):
    """Convert an IP address from binary to text.

    :param value: Raw binary data to convert
    :type value: str
    :returns: str
    """
    try:
        return socket.inet_ntop(socket.AF_INET, value)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, value)


def parse_variable_array(buf, byte_len):
    """Unpack data from buffer of specific length.

    :param buf: Buffer to operate on
    :type buf: bytes
    :param byte_len: Length to process
    :type byte_len: int
    :returns: bytes, int
    """
    _SIZE_FORMATS = ["!B", "!H", "!I", "!I"]
    if byte_len > 4:
        raise ValueError("byte_len must be <= 4")
    size_format = _SIZE_FORMATS[byte_len - 1]
    padding = b"\x00" if byte_len == 3 else b""
    size = struct.unpack(size_format, padding + buf[:byte_len])[0]
    data = buf[byte_len : byte_len + size]

    return data, size + byte_len


def ntoh(buf):
    """Convert to network order.

    :param buf: Bytes to convert
    :type buf: bytearray
    :returns: int
    """
    if len(buf) == 1:
        return buf[0]
    elif len(buf) == 2:
        return struct.unpack("!H", buf)[0]
    elif len(buf) == 4:
        return struct.unpack("!I", buf)[0]
    else:
        raise ValueError("Invalid input buffer size for NTOH")


def convert_to_ja3_segment(data, element_width):
    """Convert a packed array of elements to a JA3 segment.

    :param data: Current PCAP buffer item
    :type: str
    :param element_width: Byte count to process at a time
    :type element_width: int
    :returns: str
    """
    int_vals = list()
    data = bytearray(data)
    if len(data) % element_width:
        message = "{count} is not a multiple of {width}"
        message = message.format(count=len(data), width=element_width)
        raise ValueError(message)

    for i in range(0, len(data), element_width):
        element = ntoh(data[i : i + element_width])
        if element not in GREASE_TABLE:
            int_vals.append(element)

    return "-".join(str(x) for x in int_vals)


def process_extensions(client_handshake):
    """Process any extra extensions and convert to a JA3 segment.

    :param client_handshake: Handshake data from the packet
    :type client_handshake: dpkt.ssl.TLSClientHello
    :returns: list
    """
    if not hasattr(client_handshake, "extensions"):
        # Needed to preserve commas on the join
        return ["", "", ""]

    exts = list()
    elliptic_curve = ""
    elliptic_curve_point_format = ""
    for ext_val, ext_data in client_handshake.extensions:
        if ext_val not in GREASE_TABLE:
            exts.append(ext_val)
        if ext_val == 0x0A:
            a, b = parse_variable_array(ext_data, 2)
            # Elliptic curve points (16 bit values)
            elliptic_curve = convert_to_ja3_segment(a, 2)
        elif ext_val == 0x0B:
            a, b = parse_variable_array(ext_data, 1)
            # Elliptic curve point formats (8 bit values)
            elliptic_curve_point_format = convert_to_ja3_segment(a, 1)
        else:
            continue

    results = list()
    results.append("-".join([str(x) for x in exts]))
    results.append(elliptic_curve)
    results.append(elliptic_curve_point_format)
    return results


def ja3_scan_pcap(pcap_data):
    """Process packets within the PCAP.

    :param pcap_data: PCAP byte string to be processed
    :type pcap_data: bytes/str
    """
    results = list()

    try:
        if pcap_data.startswith((b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1")):
            reader = dpkt.pcap.Reader
        else:
            reader = dpkt.pcapng.Reader
        pcap = reader(io.BytesIO(pcap_data))
    except ValueError:
        return results

    for timestamp, buf in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
        except Exception:  # noqa: S112  # nosec: B112
            continue

        if not isinstance(eth.data, dpkt.ip.IP):
            # We want an IP packet
            continue
        if not isinstance(eth.data.data, dpkt.tcp.TCP):
            # TCP only
            continue

        ip = eth.data
        tcp = ip.data

        if len(tcp.data) <= 0:
            continue

        tls_handshake = bytearray(tcp.data)
        if (
            tls_handshake[0] != TLS_HANDSHAKE
            or tls_handshake[1] != TLS_VERSION_MAJOR
            or tls_handshake[2] not in TLS_VERSION_MINORS
        ):
            continue

        records = list()

        try:
            records, bytes_used = dpkt.ssl.tls_multi_factory(tcp.data)
        except dpkt.ssl.SSL3Exception:
            continue
        except dpkt.dpkt.NeedData:
            continue

        if len(records) <= 0:
            continue

        for record in records:
            if record.type != TLS_HANDSHAKE:
                continue
            if len(record.data) == 0:
                continue
            client_hello = bytearray(record.data)
            if client_hello[0] != 1:
                # We only want client HELLO
                continue
            try:
                handshake = dpkt.ssl.TLSHandshake(record.data)
            except dpkt.dpkt.NeedData:
                # Looking for a handshake here
                continue
            if not isinstance(handshake.data, dpkt.ssl.TLSClientHello):
                # Still not the HELLO
                continue

            client_handshake = handshake.data
            buf, ptr = parse_variable_array(client_handshake.data, 1)
            buf, ptr = parse_variable_array(client_handshake.data[ptr:], 2)
            ja3 = [str(client_handshake.version)]

            # Cipher Suites (16 bit values)
            ja3.append(convert_to_ja3_segment(buf, 2))
            ja3 += process_extensions(client_handshake)
            ja3 = ",".join(ja3)

            record = {
                "source_ip": convert_ip(ip.src),
                "destination_ip": convert_ip(ip.dst),
                "source_port": tcp.sport,
                "destination_port": tcp.dport,
                "ja3": ja3,
                "ja3_digest": md5(ja3.encode()).hexdigest(),  # noqa: S324
                "timestamp": timestamp,
                "client_hello_pkt": binascii.hexlify(tcp.data).decode("utf-8"),
            }
            results.append(record)

    return results
