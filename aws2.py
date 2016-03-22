__author__ = 'kud'
import collections
import boto
import csv
from boto.s3.connection import S3Connection

#connect to Amazon S3
conn = S3Connection("AccessKey","SecretAccessKey")



SecurityGroupRule = collections.namedtuple("SecurityGroupRule", ["ip_protocol", "from_port", "to_port", "cidr_ip",
                                                                 "src_group_name"])
#creating rules for firewall
with open("ip2.csv",'rb') as ip:
    read = csv.reader(ip)
    for row in read:
        CASSANDRA_RULES = [
            SecurityGroupRule("tcp", "22", "22", str(row[1])+"/24", None),
        ]
        SECURITY_GROUPS = [("Cassandra Cluster", CASSANDRA_RULES), ]

def get_or_create_security_group(c, group_name, description=""):
    """
    """
    groups = [g for g in c.get_all_security_groups() if g.name == group_name]
    group = groups[0] if groups else None
    if not group:
        print "Creating group '%s'..."%(group_name,)
        group = c.create_security_group(group_name, "A group for %s"%(group_name,))
    return group


def modify_sg(c, group, rule, authorize=False, revoke=False):
    src_group = None
    if rule.src_group_name:
        src_group = c.get_all_security_groups([rule.src_group_name,])[0]

    if authorize and not revoke:
        print "Authorizing missing rule %s..."%(rule,)
        group.authorize(ip_protocol=rule.ip_protocol,
                        from_port=rule.from_port,
                        to_port=rule.to_port,
                        cidr_ip=rule.cidr_ip,
                        src_group=src_group)
    elif not authorize and revoke:
        print "Revoking unexpected rule %s..."%(rule,)
        group.revoke(ip_protocol=rule.ip_protocol,
                     from_port=rule.from_port,
                     to_port=rule.to_port,
                     cidr_ip=rule.cidr_ip,
                     src_group=src_group)


def authorize(c, group, rule):
    """Authorize `rule` on `group`."""
    return modify_sg(c, group, rule, authorize=True)


def revoke(c, group, rule):
    """Revoke `rule` on `group`."""
    return modify_sg(c, group, rule, revoke=True)


def update_security_group(c, group, expected_rules):
    """
    """
    print 'Updating group "%s"...'%(group.name,)
    import pprint
    print "Expected Rules:"
    pprint.pprint(expected_rules)

    current_rules = []
    for rule in group.rules:
        if not rule.grants[0].cidr_ip:
            current_rule = SecurityGroupRule(rule.ip_protocol,
                              rule.from_port,
                              rule.to_port,
                              "0.0.0.0/0",
                              rule.grants[0].name)
        else:
            current_rule = SecurityGroupRule(rule.ip_protocol,
                              rule.from_port,
                              rule.to_port,
                              rule.grants[0].cidr_ip,
                              None)

        if current_rule not in expected_rules:
            revoke(c, group, current_rule)
        else:
            current_rules.append(current_rule)

    print "Current Rules:"
    pprint.pprint(current_rules)

    for rule in expected_rules:
        if rule not in current_rules:
            authorize(c, group, rule)


def create_security_groups():
    """
    attempts to be idempotent:
    if the sg does not exist create it,
    otherwise just check that the security group contains the rules
    we expect it to contain and updates it if it does not.
    """
    c = boto.connect_ec2()
    for group_name, rules in SECURITY_GROUPS:
        group = get_or_create_security_group(c, group_name)
        update_security_group(c, group, rules)


if __name__=="__main__":
    create_security_groups()
