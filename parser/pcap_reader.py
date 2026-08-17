"""
Telecom SIP Analyzer Pro
PCAP Reader Module

Author : Romulus Ramses
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

import pandas as pd
from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Packet


class PcapReader:
    """
    Read PCAP / PCAPNG file using Scapy.
    """

    def __init__(self, filename: str):

        self.filename = filename
        self._packets: List[Packet] = []

    def load(self) -> None:
        """
        Load packet into memory.
        """

        self._packets = rdpcap(self.filename)

    @property
    def packets(self) -> List[Packet]:
        """
        Return all packets.
        """

        return self._packets

    def packet_count(self) -> int:

        return len(self._packets)

    def file_size(self) -> int:

        return Path(self.filename).stat().st_size

    def get_ip(self, pkt: Packet) -> tuple[str, str]:

        if IP in pkt:
            return pkt[IP].src, pkt[IP].dst

        return "", ""

    def get_transport(self, pkt: Packet) -> str:

        if TCP in pkt:
            return "TCP"

        if UDP in pkt:
            return "UDP"

        return ""

    def detect_protocol(self, pkt: Packet) -> str:
        """
        Better protocol detection.
        """

        if UDP in pkt:

            sport = pkt[UDP].sport
            dport = pkt[UDP].dport

            if sport in (5060, 5061) or dport in (5060, 5061):
                return "SIP"

            if sport >= 16384 or dport >= 16384:
                return "RTP"

            return "UDP"

        if TCP in pkt:

            sport = pkt[TCP].sport
            dport = pkt[TCP].dport

            if sport in (5060, 5061) or dport in (5060, 5061):
                return "SIP"

            return "TCP"

        if IP in pkt:
            return "IP"

        return pkt.lastlayer().name

    def summary(self) -> pd.DataFrame:

        rows = []

        for number, pkt in enumerate(self._packets, start=1):

            src, dst = self.get_ip(pkt)

            rows.append(
                {
                    "Frame": number,
                    "Time": float(pkt.time),
                    "Source": src,
                    "Destination": dst,
                    "Transport": self.get_transport(pkt),
                    "Protocol": self.detect_protocol(pkt),
                    "Length": len(pkt),
                }
            )

        return pd.DataFrame(rows)
