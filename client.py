import socket
from libs.common import *
buffer_size = 2048


class Client:
    """
    Main client class for handling the file transference to the server
    """
    def __init__(self, local_addr, starting_peer_addr, chunks, ip_version=4):
        self.local_addr = local_addr
        self.starting_peer_addr = starting_peer_addr
        self.ip_version = ip_version
        self.chunks = chunks
        self.quantity_chunks = len(chunks)

    def __chunks_ids_to_bytes(self):
        return b"".join([chunk.to_bytes(2, 'big') for chunk in self.chunks])

    def __receive_request(self, sock):
        packet, addr = sock.recvfrom(buffer_size)
        print(f"<-- Received: {packet} from {addr}")
        return packet, addr

    def __request_hello(self, sock):
        request = (1).to_bytes(2, 'big') + self.quantity_chunks.to_bytes(2, 'big') \
                  + self.__chunks_ids_to_bytes()
        print(f"--> Sending: {request} to {self.starting_peer_addr}")
        sock.sendto(request, self.starting_peer_addr)

    def __receive_chunks_info(self, sock):
        packet, addr = self.__receive_request(sock)
        if int.from_bytes(packet[:2], 'big') != 3:
            self.__receive_chunks_info(sock)
        else:
            quantity_chunk = int.from_bytes(packet[2:4], 'big')
            chunks_id_list = [int.from_bytes(packet[4 + (2 * x):6 + (2 * x)], 'big')
                              for x in range(0, quantity_chunk)]
            return chunks_id_list, addr

    def connect(self):
        sock_ip_version = socket.AF_INET if self.ip_version == 4 else socket.AF_INET6
        with socket.socket(sock_ip_version, socket.SOCK_DGRAM) as sock:
            sock.bind(self.local_addr)
            self.__request_hello(sock)
            available_chunks, peer_addr = self.__receive_chunks_info(sock)
            print(f"Available chunks: {available_chunks} at {peer_addr}")
        return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        usage("client", sys.argv[0])

    local_addr = ("127.0.0.1", 5000)
    peer_addr_str = sys.argv[1].split(":")
    starting_peer_addr, chunks = (peer_addr_str[0], int(peer_addr_str[1])), \
                                  list(map(int, sys.argv[2].split(",")))

    client = Client(local_addr, starting_peer_addr, chunks)
    client.connect()
