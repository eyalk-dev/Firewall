#!/usr/bin/env python3

import socket
import struct
import datetime

show_connections_path = "/sys/class/fw/fw_con_tab/show_and_handle_connections"

# protocols
PROT_ICMP = "1"
PROT_TCP = "6"
PROT_UDP = "17"
PROT_OTHER = "255"
PROT_ANY = "143"
# actions
NF_DROP = "0"
NF_ACCEPT = "1"
# reasons
XMAS_PACKET = "-4"
NO_MATCHING_RULE = "-2"
CONNECTIONS = "-17"

connStates = {'0': "TCP_NO_CONNECTION",
              '1': "TCP_OPEN_SYN_SENT",
              '2': "TCP_OPEN_SYN_ACK_SENT",
              '3': "TCP_IS_ESTABLISHED",
              '4': "TCP_CLOSE_FIN_SENT",
              '5': "TCP_CLOSE_ONLY_ACK_SENT",
              '6': "TCP_CLOSE_FIN_ACK_SENT",
              '7': "TCP_IS_CLOSED"}


def netmask_from_size(length):
    return str(socket.htonl((0xffffffff << (32 - length)) & 0xffffffff))


def parse_rule_to_text(rule):
    rule_string = ""
    rule_params = rule.split()
    # handle params
    rule_string += rule_params[0] + " " # rule_name

    direction = rule_params[1]
    if   direction == "1":  rule_string += "in "
    elif direction == "2":  rule_string += "out "
    elif direction == "3":  rule_string += "any "

    src_redundant_mask = rule_params[4]
    if src_redundant_mask == "0": rule_string += "any "
    else:
        src_ip = int(rule_params[2])
        rule_string += socket.inet_ntoa(struct.pack('I', src_ip))
        """according to python documents, we supposed to use "!" for network repr.
        however inet_ntoa assume network repr, so we don't need network flag"""
        rule_string += "/" + src_redundant_mask + " "

    dst_redundant_mask = rule_params[7]
    if dst_redundant_mask == "0": rule_string += "any "
    else:
        dst_ip = int(rule_params[5])
        rule_string += socket.inet_ntoa(struct.pack('I', dst_ip))
        rule_string += "/" + dst_redundant_mask + " "

    protocol = rule_params[8]
    if   protocol == PROT_ICMP: rule_string += "ICMP "
    elif protocol == PROT_TCP:  rule_string += "TCP "
    elif protocol == PROT_UDP:  rule_string += "UDP "
    elif protocol == PROT_ANY:  rule_string += "any "
    else:                       rule_string += "other "

    src_port = rule_params[9]
    if   src_port == "0":    rule_string += "any "
    elif src_port == "1023": rule_string += ">1023 "
    else:                    rule_string += src_port + " "

    dst_port = rule_params[10]
    if   dst_port == "0":    rule_string += "any "
    elif dst_port == "1023": rule_string += ">1023 "
    else:                    rule_string += dst_port + " "

    ack = rule_params[11]
    if   ack == "1": rule_string += "no "
    elif ack == "2": rule_string += "yes "
    elif ack == "3": rule_string += "any "

    action = rule_params[12]
    if   action == NF_DROP:   rule_string += "drop"
    elif action == NF_ACCEPT: rule_string += "accept"

    return rule_string


def parse_rule_to_data(rule):
    rule_string = ""
    rule_params = rule.split()
    # handle params
    rule_string += rule_params[0] + " " # rule_name

    direction = rule_params[1]
    if   direction == "in":  rule_string += "1 "
    elif direction == "out": rule_string += "2 "
    elif direction == "any": rule_string += "3 "

    src_ip_string = rule_params[2];
    if src_ip_string == "any":
        rule_string += "0 0 0 "
        # rubbish ip, no mask/redundant mask, so any rule pass this mask
    else:
        src_ip_params = src_ip_string.split("/")
        src_ip = src_ip_params[0]
        rule_string += str(struct.unpack("I", socket.inet_aton(src_ip))[0]) + " "
        src_redundant_mask = src_ip_params[1]
        src_mask = netmask_from_size(int(src_redundant_mask))
        rule_string += src_mask + " " + src_redundant_mask + " "

    dst_ip_string = rule_params[3]
    if dst_ip_string == "any":
        rule_string += "0 0 0 "
        # rubbish ip, no mask/redundant mask, so any rule pass this mask
    else:
        dst_ip_params = dst_ip_string.split("/")
        dst_ip = dst_ip_params[0]
        rule_string += str(struct.unpack("I", socket.inet_aton(dst_ip))[0]) + " "
        dst_redundant_mask = dst_ip_params[1]
        dst_mask = netmask_from_size(int(dst_redundant_mask))
        rule_string += dst_mask + " " + dst_redundant_mask + " "

    protocol = rule_params[4]
    if      protocol == "ICMP": rule_string += PROT_ICMP + " "
    elif    protocol == "TCP":  rule_string += PROT_TCP  + " "
    elif    protocol == "UDP":  rule_string += PROT_UDP  + " "
    elif    protocol == "any":  rule_string += PROT_ANY  + " "
    else:                       rule_string += PROT_OTHER + " "

    src_port = rule_params[5]
    if   src_port == "any":   rule_string += "0 "
    elif src_port == ">1023": rule_string += "1023 "
    else:                     rule_string += src_port + " "

    dst_port = rule_params[6]
    if   dst_port == "any":   rule_string += "0 "
    elif dst_port == ">1023": rule_string += "1023 "
    else:                     rule_string += dst_port + " "

    ack = rule_params[7]
    if   ack == "no":  rule_string += "1 "
    elif ack == "yes": rule_string += "2 "
    elif ack == "any": rule_string += "3 "

    action = rule_params[8]
    if   action == "drop":   rule_string += NF_DROP
    elif action == "accept": rule_string += NF_ACCEPT
    rule_string += "\n"

    return rule_string


def parse_log(log):
    log_string = ""
    log_params = log.split()
    time_long = int(log_params[0])
    time_string = datetime.datetime.fromtimestamp(time_long).strftime('%d/%m/%Y %H:%M:%S')
    log_string += time_string + "\t\t"

    src_ip = int(log_params[1])
    log_string += socket.inet_ntoa(struct.pack('I', src_ip)) + "\t\t"

    dst_ip = int(log_params[2])
    log_string += socket.inet_ntoa(struct.pack('I', dst_ip)) + "\t\t"

    src_port = log_params[3]
    log_string += src_port + "\t\t"

    dst_port = log_params[4]
    log_string += dst_port + "\t\t"

    protocol = log_params[5]
    if   protocol == PROT_ICMP: log_string += "icmp\t\t"
    elif protocol == PROT_TCP:  log_string += "tcp\t\t"
    elif protocol == PROT_UDP:  log_string += "udp\t\t"
    else:                       log_string += "other\t\t"

    hooknum = log_params[6]
    log_string += hooknum + "\t\t"

    action = log_params[7]
    if   action == NF_DROP:   log_string += "drop\t"
    elif action == NF_ACCEPT: log_string += "accept\t"

    reason = log_params[8]
    if   reason == NO_MATCHING_RULE: reason = "REASON_NO_MATCHING_RULE"
    elif reason == XMAS_PACKET:      reason = "REASON_XMAS_PACKET"
    elif reason == CONNECTIONS:      reason = "REASON_CONNECTIONS"
    else: reason += "\t\t"  # for identication of output only
    log_string += reason + "\t\t"

    count = log_params[9]
    log_string += count

    return log_string


def connection_to_lst():
    lst = []
    with open(show_connections_path) as f:
        for connection in f:
            con_params = connection.split()

            src_ip = int(con_params[0])
            con_params[0] = socket.inet_ntoa(struct.pack('I', src_ip))
            src_port = int(con_params[1])
            con_params[1] = socket.ntohs(src_port)

            dst_ip = int(con_params[2])
            con_params[2] = socket.inet_ntoa(struct.pack('I', dst_ip))
            dst_port = int(con_params[3])
            con_params[3] = socket.ntohs(dst_port)

            proxy_as_server = int(con_params[4])
            con_params[4] = socket.ntohs(proxy_as_server)
            proxy_as_client = int(con_params[5])
            con_params[5] = socket.ntohs(proxy_as_client)

            # handle states
            if con_params[6] != '0':
                # non proxy connection
                con_params[6] = connStates[con_params[6]]
                lst.append(con_params[:4] + con_params[6:7])
            else:
                # proxy connection
                con_params[6] = connStates[con_params[7]]
                con_params[7] = connStates[con_params[8]]
                lst.append(con_params[:8])

    return lst
