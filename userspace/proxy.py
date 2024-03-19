#!/usr/bin/env python3

"""
    Proxy:

    For connections:  Client <-> Proxy <-> Server

    Listens on a given address for new connections,
    using epolls (checks for updates) on any open connection,
    and forwards data between associated peers

    Function to kernel on accepting new connection:
    1. Gets server address from connection table in FW, by client address.
    2. Writes proxy as client (PC) to connection table in FW, by client & server addresses.

    Based on code:
    https://somecodesnippets2.blogspot.co.il/2017/10/a-simple-python-epoll-based-proxy.html?m=1
    https://github.com/itsyarkee/python_socket_proxy/blob/master/sock_proxy.py#L107
    https://github.com/SietsevanderMolen/python-epoll-proxy/blob/master/proxy.py
"""

import socket
import select
import logging
import struct
from parser import connection_to_lst

connections_act = "/sys/class/fw/fw_con_tab/show_and_handle_connections"

eth_list = ["10.1.1.3", "10.1.2.3"]


# --- proxy to kernel helpers ---


def get_srv_from_kernel(address_client):

    cons = connection_to_lst()

    #print(cons)

    key_ip = address_client[0]
    key_port = address_client[1]
    matches = [con for con in cons if (con[0] == key_ip and con[1] == key_port)]

    if len(matches) != 1:
        print('Error: Invalid entries for connection {} : {} entries found'.format(address_client, len(matches)))
        return None

    res = (matches[0][2], int(matches[0][3]))
    return res


def add_proxy_as_client_to_kernel(addr_client, addr_server, addr_pc):

    src_ip = struct.unpack("I", socket.inet_aton(addr_client[0]))[0]
    src_port = socket.htons(addr_client[1])

    dst_ip = struct.unpack("I", socket.inet_aton(addr_server[0]))[0]
    dst_port = socket.htons(addr_server[1])

    pc_port = socket.htons(addr_pc[1])

    string = "{} {} {} {} {} {}".format(1, src_ip, src_port, dst_ip, dst_port, pc_port)

    with open(connections_act, 'w') as cons:
        cons.write(string)


class SockForward:
    """
    For each client, the proxy creates a unique socket connecting to server,
    which got from kernel
    """

    def __init__(self, socket_c):

        self.socket_c = socket_c
        addr_client = socket_c.getpeername()

        # get matching server (peer) from kernel
        self.addr_server = get_srv_from_kernel(addr_client)
        if self.addr_server is None:
            print('failed getting server from kernel')
            return

        # create peer socket
        self.peer_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ip_pc = eth_list[1] if (socket_c.getsockname()[0] == eth_list[0]) else eth_list[0]
        addr_pc = (ip_pc, 0)
        self.peer_sock.bind(addr_pc)
        addr_pc = self.peer_sock.getsockname()

        # add PC to kernel (send C-S-PC)
        add_proxy_as_client_to_kernel(addr_client, self.addr_server, addr_pc)

        self.connect_now()

    def connect_now(self):

        # try to create new connection: proxy <-> server
        try:
            self.peer_sock.settimeout(2)
            self.peer_sock.connect(self.addr_server)
            self.peer_sock.settimeout(0)
            #print('connected to server {} completed'.format(self.addr_server))

        except Exception as e:
            print('failed connecting to server {}'.format(self.addr_server))
            self.peer_sock = None
            
    def get_socket(self):
        return self.peer_sock


class Proxy:

    def __init__(self, proxy_address):

        # setup proxy object
        self.data_buffers_by_fd = {}    # send buffers for connections
        self.connections_by_fd = {}     # connections by fd dict (socket_fd <-> python_socket_obj)
        self.channels_by_fd = {}        # proxy peers/channels dict (socket A <-> socket B)

        # --- init proxy service ---

        # setup the listening socket
        self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # socket for ipv4, TCP
        self.listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.listen_socket.bind(proxy_address)
        except socket.error as e:
            print('error on listen socket {}'.format(e))
            exit(0)

        # set the socket to listen
        self.listen_socket.listen(1)  # set socket mode to listen, with backlog 1
        self.listen_socket.setblocking(0)  # set timeout to 0.0

        # use epoll
        self.epoll = select.epoll()
        self.epoll.register(self.listen_socket.fileno(), select.EPOLLIN)

        # proxy active flag
        self.running = False


    def handle_accept(self):
        #print('proxy handle_accept:')

        # get client_sock -- accepted connection
        client_sock, client_address = self.listen_socket.accept()
        logging.info(client_sock.getpeername())

        # create peer socket, and connect to Server
        peer_sock = SockForward(client_sock).get_socket()
        if peer_sock is None:
            # connection failed - discard connections
            client_sock.send(bytes("Proxy says: Can't connect to server\n", 'UTF-8'))
            client_sock.close()
            return

        # --- setup sockets for epoll-ing ---

        # client_sock
        client_sock.setblocking(0)  # set to non-block (timeout 0.0)
        self.epoll.register(client_sock.fileno(), select.EPOLLIN)

        # socket_PC
        peer_sock.setblocking(0)  # set to non-block (timeout 0.0)
        self.epoll.register(peer_sock.fileno(), select.EPOLLIN)

        # save to connections_by_fd
        self.connections_by_fd[client_sock.fileno()] = client_sock
        self.connections_by_fd[peer_sock.fileno()] = peer_sock

        # save peer coupling to channels_by_fd (2-way)
        self.channels_by_fd[client_sock.fileno()] = peer_sock
        self.channels_by_fd[peer_sock.fileno()] = client_sock

        #print('connections completed!')


    def sock_mark_for_shutdown(self, fd):

        #print('proxy sock_mark_for_shutdown:')

        # shut down socket and wait for EPOLLHUP to clean internal structures
        self.epoll.modify(fd, 0)
        self.connections_by_fd[fd].shutdown(socket.SHUT_RDWR)


    def handle_shutdown(self, fd):

        peer_fd = self.channels_by_fd[fd].fileno()
        # stop listening to socket and it's peer
        self.epoll.unregister(fd)
        self.epoll.unregister(peer_fd)

        # close both ends
        self.connections_by_fd[peer_fd].close()
        self.connections_by_fd[fd].close()

        # delete from proxy data
        del self.connections_by_fd[fd]
        del self.channels_by_fd[fd]
        if fd in self.data_buffers_by_fd:
            del self.data_buffers_by_fd[fd]

        del self.connections_by_fd[peer_fd]
        del self.channels_by_fd[peer_fd]
        if peer_fd in self.data_buffers_by_fd:
            del self.data_buffers_by_fd[peer_fd]


    def sock_receive(self, fd):
        # prefer 4096 + t*1024 recv call size
        buf_limit = 4096
        buffer = bytearray()

        # sockets set to non-block when created
        # can also use different timeout

        try:
            # keep reading into the buffer until
            # there's no more data (== timeout at non-block mode)
            while True:

                data = self.connections_by_fd[fd].recv(4096)

                if len(data) == 0:
                    # connection closed
                    break

                buffer += data
                if len(buffer) > buf_limit:
                    break

        except socket.timeout as e:
            # no data left or recv timed out
            pass

        except socket.error as e:
            # serious error on socket
            if e.errno == socket.EWOULDBLOCK:
                # EWOULDBLOCK: read all available data - it's fine
                pass
            else:
                print('ERROR: on recv socket {}'.format(e))
                pass

        # mark socket shutdown if socket closed - didn't get data
        if len(data) == 0:
            #print("didn't read data - marking socket for shutdown")
            self.sock_mark_for_shutdown(fd)

        return buffer


    def sock_forward_to_peer(self, fd, buffer):
        #print('proxy handle_incoming : forward.. ')

        # get peer
        peer_fd = self.channels_by_fd[fd].fileno()

        # if peer's buffer not empty, add new data to it
        if peer_fd in self.data_buffers_by_fd \
                and len(self.data_buffers_by_fd[peer_fd]) > 0:
            self.data_buffers_by_fd[peer_fd] += buffer
            # peer is already marked for epoll OUT
        else:
            # peer's ready to send buf is empty
            try:
                rv = self.connections_by_fd[peer_fd].send(buffer)
                if len(buffer) > rv:
                    # not all data sent - add leftover to peer's empty to send buffer
                    self.data_buffers_by_fd[peer_fd] = buffer[rv:]
                    # mark in epoll to send left data in next time
                    self.epoll.modify(fd, select.EPOLLOUT)
            except socket.error:
                self.connections_by_fd[fd].send(bytes("Can't reach server\n", 'UTF-8'))
                self.sock_mark_for_shutdown(fd)


    def handle_incoming(self, fd):

        # receive data
        buffer = self.sock_receive(fd)

        # forward data
        if len(buffer) != 0:
            # data arrived - forward
            self.sock_forward_to_peer(fd, buffer)


    def handle_outgoing(self, fd):
    
        # sanity check - check buf not empty
        if len(self.data_buffers_by_fd[fd]) == 0:
            # no data left in buffer
            self.epoll.modify(fd, select.EPOLLIN)
            return
    
        # write to socket
        rv = self.channels_by_fd[fd].send(self.data_buffers_by_fd[fd])
    
        # trim buffer
        self.data_buffers_by_fd[fd] = self.data_buffers_by_fd[fd][rv:]
    
        if len(self.data_buffers_by_fd[fd]) > 0:
            # data left in buffer
            self.epoll.modify(fd, select.EPOLLOUT)
        else:
            # no data left in buffer
            self.epoll.modify(fd, select.EPOLLIN)


    def proxy_main(self):
    
        self.running = True
    
        print('run proxy')
    
        # run main proxy loop
        try:
            while self.running:
    
                # using epolls to polls the group of sockets,
                # and returns a (possibly-empty) list of fd & event
                # for the fds that have events or errors to report.
                events = self.epoll.poll(1)  # timeout in secs
    
                # loop on polled events and handle them
                for fd, event in events:
    
                    # event on listening socket
                    if fd == self.listen_socket.fileno():
                        self.handle_accept()
    
                    # events on non-listening socket:
    
                    # waiting input
                    elif event & select.EPOLLIN:
                        self.handle_incoming(fd)
    
                    # write-ready
                    elif event & select.EPOLLOUT:
                        self.handle_outgoing(fd)
    
                    # unexpected close (hang up):  peer shutdown or error
                    elif event & (select.EPOLLHUP | select.EPOLLERR):
                        self.handle_shutdown(fd)
    
        finally:
            print('exit proxy')
            self.epoll.unregister(self.listen_socket.fileno())
            self.epoll.close()
            self.listen_socket.shutdown(socket.SHUT_RDWR)
            self.listen_socket.close()
