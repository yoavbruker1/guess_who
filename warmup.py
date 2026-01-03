from scapy.all import *
from mac_vendor_lookup import MacLookup


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
        for pack in self.packets:
            if Ether in pack:
                for mac in [pack[Ether].dst, pack[Ether].src]:
                    if mac != "ff:ff:ff:ff:ff:ff":
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
        for pack in self.packets:
            dct = {}

            if ARP in pack:
                dct["MAC"] = pack[ARP].hwsrc
                dct["IP"] = pack[ARP].psrc
                dct["VENDOR"] = self.check_vendor(dct["MAC"])

                if (dct not in info) and (dct != {}):
                    info.append(dct)
                dct = {}

                if pack[Ether].src != pack[ARP].hwsrc:
                    dct["MAC"] = pack[Ether].src
                    dct["IP"] = "UNKNOWN"
                    dct["VENDOR"] = self.check_vendor(dct["MAC"])

                    if (dct not in info) and (dct != {}):
                        info.append(dct)
                    dct = {}

            elif Ether in pack:
                dct["MAC"] = pack[Ether].src
                dct["IP"] = "UNKNOWN"
                dct["VENDOR"] = self.check_vendor(dct["MAC"])

                if (dct not in info) and (dct != {}):
                    info.append(dct)
                dct = {}

            if IP in pack:
                dct["MAC"] = "UNKNOWN"
                dct["IP"] = pack[IP].src
                dct["VENDOR"] = "UNKNOWN"
                dct["TTL"] = pack[IP].ttl

                if (dct not in info) and (dct != {}):
                    info.append(dct)
        return info

    def check_vendor(self, mac: str):
        try:
            return MacLookup().lookup(mac)
        except Exception:
            return "UNKNOWN"

    def guess_os(self, device_info: dict):
        """ "returns assumed operating system of a device"""

        if "TTL" not in device_info:
            return ["Windows", "Linux", "Unix", "MacOs", "Router"]
        ttl = device_info["TTL"]
        if ttl > 128:
            return ["Router"]
        if ttl > 64:
            return ["Windows"]
        return ["Linux", "Unix", "MacOs"]

    def __repr__(self):
        raise NotImplementedError

    def __str__(self):
        raise NotImplementedError


if __name__ == "__main__":
    network = AnalyzeNetwork("pcaps/pcap-01.pcapng")
    for ip in network.get_ips():
        info = network.get_info_by_ip(ip)
        print(ip, info, network.guess_os(info))
