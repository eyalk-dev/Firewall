#!/usr/bin/env python3

from proxy import *
import re

post_cmd1 = r'^POST /command/.*/sql/-/20'
grant_cmds = 'grant {} on {} to writer'
databases = ['database.class.ouser', 'database.function', 'database.systemclusters']
privileges = ['create', 'read', 'update', 'execute', 'delete']


class ProxyOrientDB(Proxy):

    def __init__(self):
        super().__init__(("", 24801))

    def handle_incoming(self, fd):

        # receive
        buffer = self.sock_receive(fd)

        # forward
        if len(buffer) != 0:
            # check data for exploiting attempt
            string = buffer.decode('utf-8')
            if re.match(post_cmd1, string) is not None:
                # found POST and command - check for privilege escalation attempt
                payload_index = string.find("\r\n\r\n")+4
                if payload_index == -1:
                    payload_index = string.find("\n\n")+2
                payload = string[payload_index:].lower()
                for database in databases:
                    for privilege in privileges:
                        grant_cmd = grant_cmds.format(privilege, database)
                        if grant_cmd in payload:
                            print("OrientDB: found privilege escalation attempt - DROP")
                            # shutdown connection
                            self.sock_mark_for_shutdown(fd)

            # nothing suspicious found - forward data
            self.sock_forward_to_peer(fd, buffer)


if __name__ == "__main__":
    proxy = ProxyOrientDB()
    proxy.proxy_main()
