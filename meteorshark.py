#!/usr/bin/env python3

""" Library for integrating with Meteorshark
    https://github.com/thepacketgeek/meteorshark
"""
import json
from datetime import datetime
from typing import Any, Dict, NamedTuple, Optional, Tuple

import requests
from scapy.all import (
    ARP,
    ByteField,
    Ether,
    Dot1Q,
    STP,
    Dot3,
    IP,
    IPv6,
    ICMP,
    TCP,
    UDP,
    Packet,
)


class ParsedPacket(NamedTuple):
    """ Temporary representation of a parsed packet ready to be sent
        to Meteorshark
    """

    timestamp: int
    size: int
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    ttl: Optional[int] = None
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    app_protocol: Optional[
        str
    ] = None  # The highest level protocol included in the packet
    transport_protocol: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    payload: Optional[str] = None

    def to_api(self) -> Dict[str, Any]:
        """ Prepare packet for JSON formatting """
        return {
            "timestamp": self.timestamp,
            "srcIP": self.src_ip,
            "dstIP": self.dst_ip,
            "L7protocol": self.app_protocol,
            "size": self.size,
            "ttl": self.ttl,
            "srcMAC": self.src_mac,
            "dstMAC": self.dst_mac,
            "L4protocol": self.transport_protocol,
            "srcPort": self.src_port,
            "dstPort": self.dst_port,
            "payload": self.payload,
        }


def clean_payload(pkt: Packet) -> str:
    """ Clean up packet payload from Scapy output

    """
    return pkt.layers()[-1].summary()


def get_ips(pkt: Packet) -> Tuple[Optional[str], Optional[str]]:
    if pkt.haslayer(ARP):
        return (pkt[ARP].psrc, pkt[ARP].pdst)

    if pkt.haslayer(IP):
        return (pkt[IP].src, pkt[IP].dst)
    if pkt.haslayer(IPv6):
        return (pkt[IPv6].src, pkt[IPv6].dst)

    return (None, None)


def get_macs(pkt: Packet) -> Tuple[Optional[str], Optional[str]]:
    if pkt.haslayer(Ether):
        return (pkt[Ether].src, pkt[Ether].dst)
    return (None, None)


def get_ports(pkt: Packet) -> Tuple[Optional[str], Optional[str]]:
    if pkt.haslayer(TCP):
        return (pkt[TCP].sport, pkt[TCP].dport)
    if pkt.haslayer(UDP):
        return (pkt[UDP].sport, pkt[UDP].dport)
    return (None, None)


def get_transport_protocol(pkt: Packet) -> Optional[str]:
    pass


def get_app_protocol(pkt: Packet) -> Optional[str]:
    if pkt.haslayer(ARP):
        return "ARP"
    if pkt.haslayer(ICMP):
        return "ICMP"
    else:
        for layer in reversed(pkt.layers()):
            name = layer.__name__
            if name != "Raw":
                return name
    return pkt.lastlayer().__name__


def get_payload(pkt: Packet) -> Optional[str]:
    """ Get the payload of the packet as a string """
    return f"{pkt.payload!r}"


def get_size(pkt: Packet) -> int:
    return len(pkt)


def get_ttl(pkt: Packet) -> Optional[int]:
    if IP in pkt:
        return pkt.ttl

    if IPv6 in pkt:
        return pkt.hlim

    for layer in reversed(pkt.layers()):
        ttl = getattr(pkt[layer.__name__], "ttl", None)
        if ttl:
            return ttl


def parse_packet(pkt: Packet) -> ParsedPacket:
    src_ip, dst_ip = get_ips(pkt)
    src_mac, dst_mac = get_macs(pkt)
    src_port, dst_port = get_ports(pkt)

    return ParsedPacket(
        timestamp=int(datetime.now().timestamp()),
        src_ip=src_ip,
        dst_ip=dst_ip,
        app_protocol=get_app_protocol(pkt),
        size=get_size(pkt),
        ttl=get_ttl(pkt),
        src_mac=src_mac,
        dst_mac=dst_mac,
        transport_protocol=get_transport_protocol(pkt),
        src_port=src_port,
        dst_port=dst_port,
        payload=get_payload(pkt),
    )


def upload_packet(url: str, token: str, packet: ParsedPacket):
    """ Get the Packet JSON and upload in a POST request to Meteorshark """
    headers = {"content-type": "application/json"}
    packet_data = packet.to_api()
    packet_data["owner"] = token
    headers = {"content-type": "application/json"}
    requests.post(url, data=json.dumps(packet_data), headers=headers)

