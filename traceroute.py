import argparse
import time
from scapy.layers.inet import sr1, IP, UDP, ICMP, TCP, RandShort
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6TimeExceeded
from ipwhois import IPWhois, IPDefinedError


def knock_knock(addr, proto, ttl, timeout, verbose, port):
    ipv6 = True
    if "." in addr:
        ipv6 = False
    if ipv6:
        layer = IPv6(dst=addr, hlim=ttl)
    else:
        layer = IP(dst=addr, ttl=ttl)
    if proto == "tcp":
        packet = layer / TCP(sport=RandShort(), dport=port)
    elif proto == "udp":
        packet = layer / UDP(sport=RandShort(), dport=port)
    elif proto == "icmp":
        if ipv6:
            packet = layer / ICMPv6EchoRequest()
        else:
            packet = layer / ICMP()
    else:
        raise Exception()
    t0 = time.perf_counter()
    packet = sr1(packet, timeout=timeout, verbose=0)
    t1 = time.perf_counter()
    dt = (t1 - t0) * 1000
    if not packet:
        return False
    if ipv6:
        source = packet[IPv6].src
    else:
        source = packet[IP].src
    origin = None
    if verbose and (IP in packet or IPv6 in packet):
        try:
            ipw = IPWhois(source)
            result = ipw.lookup_whois()
            origin = result.get("asn")
        except IPDefinedError:
            pass
    if (packet.haslayer(ICMPv6TimeExceeded) or
            packet.haslayer(ICMP) and packet[ICMP].type == 11):
        report = f"{ttl} {source} {dt}ms"
        if verbose:
            if not origin:
                origin = ""
            report += f"{origin}"
        print(report)
        return addr == source

    if addr == source:
        if not origin:
            origin = ""
        report = f"{ttl} {source} {dt}ms"
        if verbose:
            report += f"{origin}"
        print(report)
    else:
        print(f"{ttl} *")
    return addr == source


def traceroute(addr, proto, timeout, count, verbose=False, port=0):
    for ttl in range(count):
        target_reached = knock_knock(addr, proto, ttl, timeout, verbose, port)
        if target_reached:
            break


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='traceroute')
    parser.add_argument('-t', '--timeout', type=int, default=2,
                        help='2 sec by default')
    parser.add_argument('-p', '--port', type=int)
    parser.add_argument('-n', '--count', type=int, default=8,
                        help='maximum number of requests')
    parser.add_argument('-v', '--verbose',
                        help='output of autonomous system number'
                             'for each ip-address')
    parser.add_argument("addr", type=str, help="ip address")
    parser.add_argument("proto", choices=["tcp", "udp", "icmp"])
    args = parser.parse_args()

    traceroute(args.addr, args.proto, args.timeout,
               args.count, args.verbose,
               port=args.port)
