import socket
from libs.common import *
buffer_size = 2048


class Peer:
    def __init__(self, local_addr, ip_version=4):
        self.ip_version = socket.AF_INET if ip_version == 4 else socket.AF_INET6
        self.sock = socket.socket(self.ip_version, socket.SOCK_DGRAM)
        self.local_addr = local_addr
        self.sock.bind(self.local_addr)

    def __receive_request(self):
        packet, addr = self.sock.recvfrom(buffer_size)
        print(f"<-- Received: {packet} from {addr}")
        return packet, addr

    def __receive_hello(self):
        packet, client_addr = self.__receive_request()
        if int.from_bytes(packet[:2], 'big') != 1:
            self.__receive_hello()
        else:
            quantity_chunk = int.from_bytes(packet[2:4], 'big')
            chunks_id_list = [int.from_bytes(packet[4+(2*x):6+(2*x)], 'big')
                              for x in range(0, quantity_chunk)]
            return chunks_id_list, client_addr

    def __send_chunk_info(self):
        request = (1).to_bytes(2, 'big') + self.quantity_chunks.to_bytes(2, 'big') \
                  + self.__chunks_ids_to_bytes()
        print(f"--> Sending: {request} to {self.starting_peer_addr}")
        self.sock.sendto(request, self.starting_peer_addr)

    def connect(self):
        chunks_id_list, client_addr = self.__receive_hello()
        print(chunks_id_list, client_addr)
        self.__send_chunk_info()


if __name__ == "__main__":
    if len(sys.argv) < 4:
        usage("peer", sys.argv[0])

    local_addr = ('127.0.0.1', int(sys.argv[1]))
    peer = Peer(local_addr)
    peer.connect()
