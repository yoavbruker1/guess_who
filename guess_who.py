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
                    dct["TTL"] = pack[IP].ttl

            info.append(dct)

        for ip in remaining_ips:
            dct = {"MAC": "UNKNOWN", "IP": ip, "VENDOR": "UNKNOWN"}

            for pack in self.packets:
                if (IP in pack) and (pack[IP].src == dct["IP"]):
                    dct["TTL"] = pack[IP].ttl

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
        print(info, network.guess_os(info))
