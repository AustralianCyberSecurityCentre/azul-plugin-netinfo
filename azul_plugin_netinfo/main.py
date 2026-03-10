"""Network Info Plugin.

This plugin is responsible for featuring network telemetry extracted
from packet captures.
"""

from azul_runner import (
    Feature,
    FeatureType,
    FeatureValue,
    Job,
    Plugin,
    State,
    add_settings,
    cmdline_run,
)

from .info import extract_pcap_features
from .ja3 import ja3_scan_pcap
from .ja4.ja4 import ja4_scan_pcap


class AzulPluginNetworkInfo(Plugin):
    """Extracts network telemetry from packet captures."""

    VERSION = "2025.03.19"
    ENTITY_TYPE = "binary"
    SETTINGS = add_settings(
        filter_data_types={"*": ["network/tcpdump"]},  # handles anything with PCAP streams
    )
    FEATURES = [
        Feature(name="ja3", desc="JA3 string for TLS", type=FeatureType.String),
        Feature(name="ja3_digest", desc="JA3 digest (md5[JA3]) for TLS", type=FeatureType.String),
        Feature(name="ja4", desc="JA4 string for TLS", type=FeatureType.String),
        Feature(name="ja4_ab", desc="JA4_ab string for TLS", type=FeatureType.String),
        Feature(name="ja4_ac", desc="JA4_ac string for TLS", type=FeatureType.String),
        Feature(name="ja4_bc", desc="JA4_bc string for TLS", type=FeatureType.String),
        Feature(name="user_agent", desc="HTTP User Agent seen in requests", type=FeatureType.String),
        Feature(name="contacted_url", desc="Observed HTTP URL requested", type=FeatureType.Uri),
        Feature(name="contacted_host", desc="Network endpoint seen communicating to", type=FeatureType.Uri),
        Feature(
            name="contacted_port", desc="Destination port and protocol seen communicating on", type=FeatureType.Integer
        ),
        Feature(name="resolved_host", desc="Requested DNS resolutions", type=FeatureType.Uri),
        Feature(name="network_protocol", desc="Network protocol observed", type=FeatureType.String),
    ]

    def execute(self, job: Job):
        """Process available pcaps and feature any interesting network features."""
        if not job.get_all_data(file_format="network/tcpdump"):
            return State.Label.OPT_OUT

        for data in job.get_all_data(file_format="network/tcpdump"):
            features = {}

            p = data.read()
            for result in ja3_scan_pcap(p):
                features.setdefault("ja3", set()).add(result["ja3"])
                features.setdefault("ja3_digest", set()).add(result["ja3_digest"])

            for result in ja4_scan_pcap(p):
                features.setdefault("ja4", set()).add(result["ja4"])
                features.setdefault("ja4_ab", set()).add(result["ja4_ab"])
                features.setdefault("ja4_ac", set()).add(result["ja4_ac"])
                features.setdefault("ja4_bc", set()).add(result["ja4_bc"])

            result = extract_pcap_features(p)
            if result["user-agents"]:
                features["user_agent"] = result["user-agents"]
            if result["contacted_urls"]:
                features["contacted_url"] = result["contacted_urls"]
            if result["contacted_hosts"]:
                features["contacted_host"] = result["contacted_hosts"]
            if result["resolved_hosts"]:
                features["resolved_host"] = result["resolved_hosts"]
            if result["protocols"]:
                features["network_protocol"] = result["protocols"]
            for port, prot in result["contacted_ports"]:
                features.setdefault("contacted_port", set()).add(FeatureValue(port, label=prot))

            # we record interesting features in the info section too
            pinfo = {}
            if features.get("ja3_digest"):
                pinfo["ja3_digest"] = list(sorted(features["ja3_digest"]))
            if features.get("contacted_host"):
                pinfo["contacted_host"] = list(sorted(features["contacted_host"]))
            if features.get("contacted_url"):
                pinfo["contacted_url"] = list(sorted(features["contacted_url"]))
            if features.get("resolved_host"):
                pinfo["resolved_host"] = list(sorted(features["resolved_host"]))
            if features.get("user_agent"):
                pinfo["user_agent"] = list(sorted(features["user_agent"]))

            if features or pinfo:
                de = self.get_data_event(data.file_info.sha256)
                de.add_many_feature_values(features)
                de.add_info({"pcapinfo": pinfo})


def main():
    """Run plugin via command-line."""
    cmdline_run(plugin=AzulPluginNetworkInfo)


if __name__ == "__main__":
    main()
