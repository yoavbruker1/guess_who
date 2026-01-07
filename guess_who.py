from scapy.all import *
from mac_vendor_lookup import MacLookup

WINDOWS_TTL = 128
LINUX_TTL = 64


class AnalyzeNetwork:
    def __init__(self, pcap_path: str):
        """
        pcap_path (string): path to a pcap file
        """

        self.packets = rdpcap(pcap_path)

    def get_ips(self):
        """returns a list of ip addresses (strings) that appear in
        the pcap"""

        ips = set()
        for pack in self.packets:
            if ARP in pack:
                for ip in [pack[ARP].psrc, pack[ARP].pdst]:
                    ips.add(ip)
            if IP in pack:
                for ip in [pack[IP].src, pack[IP].dst]:
                    ips.add(ip)
        return list(ips)

    def get_macs(self):
        """returns a list of MAC addresses (strings) that appear in
        the pcap"""

        macs = set()
        exceptions = ["ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"]
        for pack in self.packets:
            if Ether in pack:
                for mac in [pack[Ether].dst, pack[Ether].src]:
                    if mac not in exceptions:
                        macs.add(mac)
            if ARP in pack:
                for mac in [pack[ARP].hwdst, pack[ARP].hwsrc]:
                    if (mac not in exceptions) and (mac not in macs):
                        macs.add(mac)
        return list(macs)

    def get_info_by_mac(self, mac: str):
        """returns a dict with all information about the device with
        given MAC address"""

        for item in self.get_info():
            if item["MAC"] == mac:
                return item
        return {"MAC": mac, "IP": "UNKNOWN", "VENDOR": self.check_vendor(mac)}

    def get_info_by_ip(self, ip: str):
        """returns a dict with all information about the device with
        given IP address"""

        for item in self.get_info():
            if item["IP"] == ip:
                return item
        return {"MAC": "UNKNOWN", "IP": ip, "VENDOR": "UNKNOWN"}

    def get_info(self):
        """returns a list of dicts with information about every
        device in the pcap"""

        info = []
        macs = self.get_macs()
        remaining_ips = self.get_ips()
        for mac in macs:
            dct = {"MAC": mac, "IP": "UNKNOWN", "VENDOR": self.check_vendor(mac)}
            for pack in self.packets:
                if (ARP in pack) and (pack[ARP].hwsrc == mac):
                    dct["IP"] = pack[ARP].psrc

                    if dct["IP"] in remaining_ips:
                        remaining_ips.remove(dct["IP"])

                if (IP in pack) and (pack[IP].src == dct["IP"]):
                    self.add_info(pack, dct)

            info.append(dct)

        for ip in remaining_ips:
            dct = {"MAC": "UNKNOWN", "IP": ip, "VENDOR": "UNKNOWN"}

            for pack in self.packets:
                if (IP in pack) and (pack[IP].src == dct["IP"]):
                    self.add_info(pack, dct)

            info.append(dct)

        return info

    def add_info(self, pack, dct):
        """ "Adds additional info to a packet, based on layer 3+"""

        if IP in pack:
            dct["TTL"] = pack[IP].ttl

        if ICMP in pack:
            load = bytes(pack[ICMP].payload)
            for offset in [0, 16]:
                # Check for load with/without timestamp (16 byte difference)
                if len(load) >= 3 + offset:
                    if load[0 + offset : 3 + offset] == b"abc":
                        dct["PAYLOAD FORMAT"] = "Alphabet"
                    if load[0 + offset : 3 + offset] == b"\x10\x11\x12":
                        dct["PAYLOAD FORMAT"] = "BSD"

        if Raw in pack:
            load = bytes(pack[Raw])
            if b"HTTP" in load:
                load = str(load, "utf-8")
                sides = {"Server: ": "Server", "User-Agent: ": "Client"}

                for side in ["Server: ", "User-Agent: "]:
                    sw_start = load.find(side)
                    if sw_start > -1:
                        sw_start += len(side)
                        sw_end = sw_start + load[sw_start:].find("\r")

                        dct["SOFTWARE"] = load[sw_start:sw_end]
                        dct["SIDE"] = sides[side]

    def check_vendor(self, mac: str):
        """ "Checks a mac's vendor"""

        try:
            return MacLookup().lookup(mac)
        except Exception:
            return "UNKNOWN"

    def guess_os(self, device_info: dict):
        """ "returns assumed operating system of a device"""

        # Check for load format
        if "PAYLOAD FORMAT" in device_info:
            format = device_info["PAYLOAD FORMAT"]
            if format == "Alphabet":
                return "Windows"
            if format == "BSD":
                return ["Linux", "Unix", "MacOs"]

        # Check for ttl
        if "TTL" in device_info:
            ttl = device_info["TTL"]
            if ttl > WINDOWS_TTL:
                return "Router"
            if ttl > LINUX_TTL:
                return "Windows"
            return ["Linux", "Unix", "MacOs"]

        return ["Linux", "Unix", "MacOs", "Windows", "Router"]

    def __repr__(self):
        raise NotImplementedError

    def __str__(self):
        raise NotImplementedError


if __name__ == "__main__":
    network = AnalyzeNetwork("pcaps/pcap-03.pcapng")
    for ip in network.get_ips():
        info = network.get_info_by_ip(ip)
        print(info)
