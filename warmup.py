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
            if Ether in pack:
                dct = {}
                flag = False
                for item in info:
                    if item["MAC"] == pack[Ether].src:
                        if item["IP"] == "UNKNOWN" and (ARP in pack):
                            dct = item
                        else:
                            flag = True
                        break

                dct["MAC"] = pack[Ether].src
                dct["IP"] = "UNKNOWN"
                dct["VENDOR"] = self.check_vendor(dct["MAC"])

            if flag:
                pass

            if ARP in pack:
                if pack[ARP].hwsrc != pack[Ether].src:
                    dct["IP"] = "UNKNOWN"
                else:
                    dct["IP"] = pack[ARP].psrc

            if dct not in info:
                info.append(dct)
        return info

    def check_vendor(self, mac: str):
        try:
            return MacLookup().lookup(mac)
        except Exception:
            return "UNKNOWN"

    def __repr__(self):
        raise NotImplementedError

    def __str__(self):
        raise NotImplementedError
