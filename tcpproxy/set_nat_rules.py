
import iptc
from iptc.easy import flush_all


def set_rule():
    try:
        chain = iptc.Chain(iptc.Table(iptc.Table.NAT), "POSTROUTING")
        chain.flush()
        rule = iptc.Rule()
        rule.src = "192.168.0.0/24"
        rule.dst = "192.168.1.0/24"
        target = iptc.Target(rule, "MASQUERADE")
        rule.target = target
        chain.insert_rule(rule)

        rule1 = iptc.Rule()
        rule1.out_interface = "eth0"
        target1 = iptc.Target(rule1, "MASQUERADE")
        rule1.target = target1
        chain.insert_rule(rule1)

        chain1 = iptc.Chain(iptc.Table(iptc.Table.NAT), "PREROUTING")
        chain1.flush()
        # rule2 = iptc.Rule()
        # #rule2.protocol = "tcp"
        # rule2.src = "192.168.0.0/24"
        # rule2.dst = "192.168.0.100"
        # match = iptc.Match(rule2, "tcp")
        # match.dport = "61122"
        # rule2.add_match(match)
        # target2 = iptc.Target(rule2, "DNAT")
        # target2 = "192.168.0.100:1080"
        # rule2.target = target2
        # chain1.insert_rule(rule2)
    except Exception as ex:
        print('your input is incorrect')


