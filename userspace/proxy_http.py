#!/usr/bin/env python3

from proxy import *
import DLP


class ProxyHTTP(Proxy):

    def __init__(self):
        super().__init__(("", 8001))

    def handle_incoming(self, fd):

        # receive
        buffer = self.sock_receive(fd)

        # forward
        if len(buffer) != 0:
            # data arrived - filter according to Content-Length
            string = buffer.decode('utf-8')

            payload_index = string.find("\r\n\r\n")+4
            payload = string[payload_index:]
            is_code_c = DLP.check_for_code_c(payload)
            if is_code_c:
                # drop data and close connection
                print("HTTP: tried to leak C code - DROP")
                self.sock_mark_for_shutdown(fd)
            else:
                # forward data
                print("HTTP: not C code - ACCEPT")
                self.sock_forward_to_peer(fd, buffer)


if __name__ == "__main__":
    proxy = ProxyHTTP()
    proxy.proxy_main()

