#!/usr/bin/env python3

import sys
from parser import *

active = "/sys/class/fw/fw_rules/active"
manage_rules = "/sys/class/fw/fw_rules/handle_rules"
log_path = "/dev/fw_log"
clear_log = "/sys/class/fw/fw_log/log_clear"
clear_connections = "/sys/class/fw/fw_con_tab/clear_connections"

log_descript = "timestamp			src_ip			dst_ip			src_port	dst_port	protocol	hooknum		action	reason				count"

PAGE_SIZE = 4096
MAX_RULES = 50


def show_rules():
    with open(manage_rules, "r") as f:
        for rule in f:
            print(parse_rule_to_text(rule))


def load_rules(file_path):
    with open(file_path, "r") as f_input:
        rules_data = ""
        rules_num = 0
        for rule in f_input:
            rules_data += parse_rule_to_data(rule)
            rules_num += 1
            if rules_num >= MAX_RULES: break

        assert (len(rules_data) <= PAGE_SIZE), "rules pass PAGE_SIZE"
        with open(manage_rules, "w") as f_output:
            f_output.write(rules_data)


def show_log():
    with open(log_path) as f:
        print(log_descript)
        for log in f:
            print(parse_log(log))


def show_connections():
    lst = connection_to_lst()
    for con in lst:
        print("\t".join(str(e) for e in con))


if __name__ == "__main__":
    assert (2 <= len(sys.argv) <= 3), "only one or two args is legal"

    cmd = sys.argv[1]

    if cmd != "load_rules": # need command only
        assert (len(sys.argv) == 2), "too many args"

    # check commands
    if cmd == "activate":
        with open(active, 'w') as f:
            f.write("1")

    elif cmd == "deactivate":
        with open(active, 'w') as f:
            f.write("0")

    elif cmd == "show_rules":
        show_rules()

    elif cmd == "clear_rules":
        # clear connections
        with open(clear_connections, 'w') as f:
            f.write(" ")
        with open(manage_rules, 'w') as g:
            g.write(" ")  # writing to manage_rules clear previus rules

    elif cmd == "load_rules":
        assert (len(sys.argv) == 3), "path not specified"
        # clear connections
        with open(clear_connections, 'w') as f:
            f.write(" ")
        path = sys.argv[2]
        load_rules(path)

    elif cmd == "show_log":  # work in super user only
        show_log()

    elif cmd == "clear_log":
        with open(clear_log, 'w') as f:
            f.write("0")

    elif cmd == "show_connections":
        show_connections()

    else:
        print("invalid command")
