"""Extract metadata of network activity from a PCAP."""

import io
import ipaddress
import pprint
import sys

import dpkt
from pydantic import TypeAdapter, ValidationError
from pydantic.networks import AnyUrl

anyUrlAdapter = TypeAdapter(AnyUrl)


def extract_pcap_features(pcap_data):
    """Process packets within the PCAP.

    :param pcap_data: PCAP byte string to be processed
    :type pcap_data: bytes/str
    """
    results = {
        "contacted_hosts": set(),
        "resolved_hosts": set(),
        "contacted_urls": set(),
        "contacted_ports": set(),
        "user-agents": set(),
        "protocols": set(),
    }

    try:
        if pcap_data.startswith((b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1")):
            reader = dpkt.pcap.Reader
        else:
            reader = dpkt.pcapng.Reader
        pcap = reader(io.BytesIO(pcap_data))
    except ValueError:
        return results

    for _, buf in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
        except Exception:
            # might be layer 3 capture
            try:
                ip = dpkt.ip.IP(buf)
            except Exception:  # noqa: S112  # nosec: B112
                # skip anything else for now
                continue

        last = l3 = l4 = dest = port = None
        if isinstance(ip, dpkt.ip.IP):
            _ = ipaddress.IPv4Address(ip.src)
            dest = ipaddress.IPv4Address(ip.dst)
            l3 = "IPv4"
        elif isinstance(ip, dpkt.ip6.IP6):
            _ = ipaddress.IPv6Address(ip.src)
            dest = ipaddress.IPv6Address(ip.dst)
            l3 = "IPv6"
        else:
            continue

        if isinstance(ip.data, dpkt.tcp.TCP):
            port = ip.data.dport
            l4 = "TCP"
        elif isinstance(ip.data, dpkt.udp.UDP):
            port = ip.data.dport
            l4 = "UDP"
        elif isinstance(ip.data, dpkt.icmp.ICMP):
            l4 = "ICMP"  # not really but gives desired result
        else:
            continue

        # FUTURE: only record server side for stream based protos ignore any local, multicast, reserved, etc. addresses
        if dest and dest.is_global and not dest.is_multicast:
            dstr = str(dest)
            # url form of address string to prevent ambiguous port
            if isinstance(dest, ipaddress.IPv6Address):
                dstr = "[%s]" % str(dest)
            if port:
                dstr += ":%d" % port
            if port and ip.data.data:
                last = (port, l4)
            results["contacted_hosts"].add(dstr)
            results["protocols"].add(l3)
            results["protocols"].add(l4)

        try:
            # Parse http request
            http = dpkt.http.Request(ip.data.data)
            method = http.method
            uri = http.uri
            host = http.headers.get("host")
            agent = http.headers.get("user-agent")

            if uri and method:
                results["protocols"].add("HTTP")
                last = (port, "HTTP")
            if uri and uri.lower().startswith(("http://", "https://", "ftp://")):
                anyUrlAdapter.validate_python(uri)
                results["contacted_urls"].add(uri)
            elif uri and host:
                new_url = "http://" + host + uri
                try:
                    anyUrlAdapter.validate_python(new_url)
                except ValidationError:
                    new_url = "http://" + host
                    anyUrlAdapter.validate_python(new_url)

                results["contacted_urls"].add(new_url)

            if agent:
                results["user-agents"].add(agent)

        except Exception:  # noqa: S110  # nosec: B110
            pass

        try:
            dns = dpkt.dns.DNS(ip.data.data)
            # types we want to log resolutions for
            types = [
                dpkt.dns.DNS_A,
                dpkt.dns.DNS_AAAA,
                dpkt.dns.DNS_CNAME,
                dpkt.dns.DNS_MX,
                dpkt.dns.DNS_PTR,
                dpkt.dns.DNS_NS,
                dpkt.dns.DNS_SOA,
                dpkt.dns.DNS_TXT,
            ]
            # FUTURE: use this as a feature value.
            if dns.qd and dns.qd[0].name and dns.qd[0].type in types:
                results["protocols"].add("DNS")
                results["resolved_hosts"].add(dns.qd[0].name)
                # only want to log outgoing port
                if not dns.an and not ip.data.sport == 53:
                    last = (port, "DNS")
        except Exception:  # noqa: S110  # nosec: B110
            pass

        try:
            ssl = dpkt.ssl.TLSRecord(ip.data.data)
            # only want to log when outgoing
            rec = dpkt.ssl.RECORD_TYPES[ssl.type](ssl.data)
            if isinstance(rec.data, dpkt.ssl.TLSClientHello):
                results["protocols"].add("TLS")
                last = (port, "TLS")

        except Exception:  # noqa: S110  # nosec: B110
            pass

        if last:
            results["contacted_ports"].add(last)
    return results


if __name__ == "__main__":
    """Command-line testing of extraction."""
    if len(sys.argv) != 2:
        print("Expect single pcap path as argument")

    with open(sys.argv[1], "rb") as tmp:
        pprint.pprint(extract_pcap_features(tmp.read()), indent=2, width=120)
