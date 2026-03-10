"""Slight modification of `https://github.com/FoxIO-LLC/ja4/blob/main/python/ja4.py`.

Copyright (c) 2023, FoxIO, LLC.
All rights reserved.
Patent Pending
JA4 is Open-Source, Licensed under BSD 3-Clause

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

# ruff: noqa: D103, E741, S603

import json
import os
import tempfile
from subprocess import PIPE, Popen

from .common import (
    GREASE_TABLE,
    TLS_MAPPER,
    cache_update,
    get_cache,
    get_hex_sorted,
    get_signature_algorithms,
    get_supported_version,
    normalize_tls_fields,
    scan_tls,
    sha_encode,
)

keymap = {
    "frame": {"frno": "number", "protos": "protocols", "timestamp": "time_epoch"},
    "ip": {"src": "src", "dst": "dst", "ttl": "ttl"},
    "ipv6": {"src": "src", "dst": "dst", "ttl": "hlim"},
    "tcp": {
        "flags": "flags",
        "ack": "ack",
        "seq": "seq",
        "fin": "flags_fin",
        "stream": "stream",
        "srcport": "srcport",
        "dstport": "dstport",
        "len": "len",
        "flags_ack": "flags_ack",
    },
    "udp": {
        "stream": "stream",
        "srcport": "srcport",
        "dstport": "dstport",
    },
    "quic": {
        "packet_type": "long_packet_type",
    },
    "tls": {
        "version": "handshake_version",
        "type": "handshake_type",
        "extensions": "handshake_extension_type",
        "ciphers": "handshake_ciphersuite",
        "domain": "handshake_extensions_server_name",
        "supported_versions": "handshake_extensions_supported_version",
        "alpn": "handshake_extensions_alps_alpn_str",
        "alpn_list": "handshake_extensions_alpn_str",
        "sig_alg_lengths": "handshake_sig_hash_alg_len",
        "signature_algorithms": "handshake_sig_hash_alg",
    },
    "x509af": {
        "cert_extensions": "extension_id",
        "extension_lengths": "extensions",
        "subject_sequence": "rdnSequence",
    },
    "http": {
        "method": "request_method",
        "headers": "request_line",
        "cookies": "cookie",
        "lang": "accept_language",
    },
    "http2": {
        "method": "headers_method",
        "headers": "header_name",
        "lang": "headers_accept_language",
        "cookies": "headers_set_cookie",
        # "cookies": "headers_cookie", Duplicate key???
    },
    "ssh": {
        "ssh_protocol": "protocol",
        "hassh": "kex_hassh",
        "hassh_server": "kex_hasshserver",
        "direction": "direction",
        "algo_client": "encryption_algorithms_client_to_server",
        "algo_server": "encryption_algorithms_server_to_client",
    },
}


def to_ja4(x, debug_stream) -> dict[str, str]:
    """Convert the values stored in x to a dictionary containing ja4, ja4_ab, ja4_ac, and ja4_bc."""
    if x["stream"] == debug_stream:
        print(f"computing ja4 for stream {x['stream']}")
    ptype = "q" if x["quic"] else "t"

    if "extensions" not in x:
        x["extensions"] = []

    if "ciphers" not in x:
        x["ciphers"] = []

    normalize_tls_fields(x, extensions_prefix="0x")
    ext_len = "{:02d}".format(min(len([x for x in x["extensions"] if x not in GREASE_TABLE]), 99))
    cache_update(x, "client_ciphers", x["ciphers"], debug_stream)

    if "0x000d" in x["extensions"]:
        x["signature_algorithms"] = [y[2:] for y in get_signature_algorithms(x)]
    else:
        x["signature_algorithms"] = ""

    cache_update(x, "client_extensions", x["extensions"], debug_stream)

    x["sorted_extensions"], _len, _ = get_hex_sorted(x, "extensions")
    x["original_extensions"], _len, _ = get_hex_sorted(x, "extensions", sort=False)
    if x["signature_algorithms"] == "":
        x["sorted_extensions"] = x["sorted_extensions"]
        x["original_extensions"] = x["original_extensions"]
    else:
        x["sorted_extensions"] = x["sorted_extensions"] + "_" + ",".join(x["signature_algorithms"])
        x["original_extensions"] = x["original_extensions"] + "_" + ",".join(x["signature_algorithms"])

    if x["extensions"]:
        sorted_extensions = sha_encode(x["sorted_extensions"])
        # original_extensions = sha_encode(x["original_extensions"])
    else:
        sorted_extensions = "000000000000"
        # original_extensions = "000000000000"

    x["sorted_ciphers"], cipher_len, sorted_ciphers = get_hex_sorted(x, "ciphers")
    x["original_ciphers"], cipher_len, original_ciphers = get_hex_sorted(x, "ciphers", sort=False)

    if not x["ciphers"]:
        sorted_ciphers = "000000000000"
        # original_ciphers = "000000000000"
        cipher_len = "00"

    sni = "d" if "domain" in x else "i"
    x["version"] = x["version"][0] if isinstance(x["version"], list) else x["version"]
    if "supported_versions" in x:
        x["version"] = get_supported_version(x["supported_versions"])
    version = TLS_MAPPER[x["version"]] if x["version"] in TLS_MAPPER else "00"

    alpn = "00"
    if "alpn_list" in x:
        if isinstance(x["alpn_list"], list):
            alpn = x["alpn_list"][0]
        else:
            alpn = x["alpn_list"]

    if len(alpn) > 2:
        alpn = f"{alpn[0]}{alpn[-1]}"

    if ord(alpn[0]) > 127:
        alpn = "99"

    entry = get_cache(x)[x["stream"]]
    if not entry.get("count"):
        idx = 0
    else:
        idx = entry["count"]
    idx += 1
    cache_update(x, "count", idx, debug_stream)

    a = f"{ptype}{version}{sni}{cipher_len}{ext_len}{alpn}"
    b = f"{sorted_ciphers}"
    c = f"{sorted_extensions}"

    res: dict[str, str] = {}

    res["ja4"] = f"{a}_{b}_{c}"
    res["ja4_ab"] = f"{a}_{b}"
    res["ja4_ac"] = f"{a}_{c}"
    res["ja4_bc"] = f"{b}_{c}"
    res["ja4_ro"] = (
        f"{ptype}{version}{sni}{cipher_len}{ext_len}{alpn}_{x['original_ciphers']}_{x['original_extensions']}"
    )

    # Add these flavors of ja4 in the future if required
    # res["ja4_o"] = f"{a}_{original_ciphers}_{original_extensions}"
    # res["ja4_r"] = f"{ptype}{version}{sni}{cipher_len}{ext_len}{alpn}_{x['sorted_ciphers']}_{x['sorted_extensions']}"

    return res


# Layer update is a common function to update different layer
# parameters into the packet.
def layer_update(x, pkt, layer):
    l = None
    x["hl"] = layer

    if layer == "quic":
        quic = pkt["layers"].pop("quic", None)
        if quic:
            if isinstance(quic, list):
                quic = quic[0]
            [
                x.update({key: quic[f"{layer}_{layer}_{item}"]})
                for key, item in keymap[layer].items()
                if f"{layer}_{layer}_{item}" in quic
            ]
            l = quic["tls"] if "tls" in quic.keys() else None
            layer = "tls"
    else:
        l = pkt["layers"].pop(layer, None) if layer != "x509af" else pkt["layers"].pop("tls", None)

    if layer == "tls":
        l = scan_tls(l)
    else:
        l = l[0] if isinstance(l, list) else l

    if l:
        [
            x.update({key: l[f"{layer}_{layer}_{item}"]})
            for key, item in keymap[layer].items()
            if f"{layer}_{layer}_{item}" in l
        ]

    if layer == "x509af" and l:
        [x.update({key: l[f"tls_tls_{item}"]}) for key, item in keymap["tls"].items() if f"tls_tls_{item}" in l]
        x.update({"issuer_sequence": l["x509if_x509if_rdnSequence"]}) if "x509if_x509if_rdnSequence" in l else None
        if "x509if_x509if_id" in l:
            x.update({"rdn_oids": l["x509if_x509if_id"]})
        if "x509if_x509if_oid" in l:
            x.update({"rdn_oids": l["x509if_x509if_oid"]})
        x.update(
            {"printable_certs": l["x509sat_x509sat_printableString"]}
        ) if "x509sat_x509sat_printableString" in l else None

    # Some extension types are a list bug #29
    if "type" in x and isinstance(x["type"], list):
        x["type"] = x["type"][0]


def ja4_scan_pcap(buf: bytes) -> list[dict[str, str]]:
    """Scan a buffer containing pcap data and return all ja4-related information in a dictionary."""
    res: list[dict[str, str]] = []

    STREAM = -1  # minimize modifications to original logic

    with tempfile.NamedTemporaryFile(delete=False) as f_in_tmp:
        try:
            f_in_tmp.write(buf)
            f_in_tmp.flush()

            ps = Popen(["/usr/bin/tshark", "-r", f_in_tmp.name, "-T", "ek", "-n"], stdout=PIPE, encoding="utf-8")

            if ps.stdout is None:
                return res

            for _, line in enumerate(iter(ps.stdout.readline, "")):
                if "layers" in line:
                    pkt = json.loads(line)

                    x = {}
                    layer_update(x, pkt, "frame")
                    layer_update(x, pkt, "ip") if "ipv6" not in x["protos"] else layer_update(x, pkt, "ipv6")

                    if "tcp" in x["protos"]:
                        layer_update(x, pkt, "tcp")
                        if "ocsp" in x["protos"] or "x509ce" in x["protos"]:
                            layer_update(x, pkt, "x509af")
                        elif "http" in x["protos"]:
                            if "http2" in x["protos"]:
                                layer_update(x, pkt, "http2")
                            else:
                                layer_update(x, pkt, "http")
                        elif "tls" in x["protos"]:
                            layer_update(x, pkt, "tls")
                        elif "ssh" in x["protos"]:
                            layer_update(x, pkt, "ssh")
                        x["quic"] = False

                    elif "udp" in x["protos"] and "quic" in x["protos"]:
                        layer_update(x, pkt, "udp")
                        layer_update(x, pkt, "quic")
                        x["quic"] = True
                    else:
                        continue

                    if "stream" not in x:
                        continue

                    # We update the stream value into the cache first
                    # to start recording this entry and then the tuple as well
                    x["stream"] = int(x["stream"])

                    [
                        cache_update(x, key, x[key], STREAM)
                        for key in ["stream", "src", "dst", "srcport", "dstport", "protos"]
                    ]

                    if x["hl"] == "tls" and x.get("type") == "1":
                        try:
                            res.append(to_ja4(x, STREAM))
                        except Exception as e:
                            print(e)
                            pass
        finally:
            os.unlink(f_in_tmp.name)
    return res
