#!/usr/bin/env python3

from proxy import *
from email import parser
import DLP


class ProxySMTP(Proxy):

    def __init__(self):
        super().__init__(("", 2500))
        self.sent_DATA_cmd_by_fd = {}  # if this socket sent DATA cmd
        self.parser = parser.Parser()

    def handle_incoming(self, fd):

        # receive
        buffer = self.sock_receive(fd)

        # forward
        if len(buffer) != 0:
            string = buffer.decode('utf-8')

            # data arrived - check if followed DATA cmd
            if fd in self.sent_DATA_cmd_by_fd and self.sent_DATA_cmd_by_fd[fd] is True:
                # sent DATA cmd - so now it's the data we need to check

                # parse message from email
                email = self.parser.parsestr(string)
                message = email.get_payload()
                if email.is_multipart():
                    message = '\r\n'.join(message)

                # check for code c
                is_code_c = DLP.check_for_code_c(message)
                if is_code_c:
                    # drop data and close connection
                    print("SMTP: tried to leak C code - DROP")
                    self.sock_mark_for_shutdown(fd)
                else:
                    print("SMTP: not C code - ACCEPT")

            # if not followed by DATA cmd - check for DATA cmd
            elif string[:4] == "DATA":
                self.sent_DATA_cmd_by_fd[fd] = True

            # forward data
            self.sock_forward_to_peer(fd, buffer)


if __name__ == "__main__":
    proxy = ProxySMTP()
    proxy.proxy_main()

