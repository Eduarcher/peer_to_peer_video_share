import socket
from libs.common import *
from time import sleep
import constants as const

BUFFER_SIZE = const.buffer_size


def decode_key_values_from_file(addr):
    try:
        key_values_file = open(addr, "r")
        chunks_dict = {}
        while True:
            line = key_values_file.readline()
            if len(line) <= 0:
                break
            chunk_id, chunk_file_name = line.split(sep=": ")
            chunk_file_name_split = chunk_file_name.split('.')
            chunk_file_name = chunk_file_name_split[0] + '.' + chunk_file_name_split[1][:3]
            chunks_dict[int(chunk_id)] = chunk_file_name
        return chunks_dict
    except Exception as e:
        print("ERROR: Key values file not found or invalid.")
        sys.exit()


def get_peers_connected_from_file(peers_addr):
    try:
        return [(peer.split(":")[0], int(peer.split(":")[1])) for peer in peers_addr]
    except Exception as e:
        print("ERROR: Peer input error, possible invalid peer address. Failed to initialize.")
        sys.exit()


class Peer:
    def __init__(self, local_addr, local_chunks, peers_connected, ip_version=4):
        self.ip_version = socket.AF_INET if ip_version == 4 else socket.AF_INET6
        self.sock = socket.socket(self.ip_version, socket.SOCK_DGRAM)
        self.local_addr = local_addr
        self.sock.bind(self.local_addr)
        self.local_chunks = local_chunks
        self.peers_connected = peers_connected

    def __get_available_chunks_ids(self, chunks):
        return sorted(list(set(self.local_chunks).intersection(chunks)))

    def __chunks_ids_to_bytes(self, chunks):
        return b"".join([chunk.to_bytes(2, "big") for chunk in chunks])

    def format_addr_for_query(self, addr):
        return b"".join([int(num).to_bytes(1, "big") for num in addr[0].split('.')]) \
               + addr[1].to_bytes(2, 'big')

    def __receive_request(self):
        packet, addr = self.sock.recvfrom(BUFFER_SIZE)
        print(f"<-- Received: {packet} from {addr}")
        return packet, addr

    def __unpack_chunk_request(self, packet):
        quantity_chunk = int.from_bytes(packet[:2], "big")
        chunks_id_list = [int.from_bytes(packet[2 + (2 * x):4 + (2 * x)], "big")
                          for x in range(quantity_chunk)]
        return chunks_id_list

    def __send_query(self, chunks, addr, ttl=None, origin=None):
        ttl = const.initial_peer_ttl if ttl is None else ttl
        if ttl > 0:
            addr = self.format_addr_for_query(addr)
            query = (2).to_bytes(2, "big") + addr + ttl.to_bytes(2, 'big') \
                        + len(chunks).to_bytes(2, 'big') + self.__chunks_ids_to_bytes(chunks)
            print(f"Sending: {query} to connected peers")
            for peer_addr in self.peers_connected:
                if peer_addr != origin:
                    print(f"--> Sending query to {peer_addr}")
                    self.sock.sendto(query, peer_addr)

    def __unpack_query(self, packet):
        addr_ip = ".".join(str(num) for num in packet[2:6])
        addr_port = int.from_bytes(packet[6:8], 'big')
        ttl = int.from_bytes(packet[8:10], 'big')
        chunks = self.__unpack_chunk_request(packet[10:])
        return (addr_ip, addr_port), ttl, chunks

    def __send_chunk_info(self, chunks_list, client_addr):
        available_chunks = self.__get_available_chunks_ids(chunks_list)
        response = (3).to_bytes(2, "big") + len(available_chunks).to_bytes(2, "big") \
                    + self.__chunks_ids_to_bytes(available_chunks)
        print(f"--> Sending: {response} to {client_addr}")
        self.sock.sendto(response, client_addr)

    def __send_response_chunks(self, chunks, client_addr):
        for chunk in chunks:
            chunk_data = open("data/" + self.local_chunks[chunk], "rb").read(1024)
            response = (5).to_bytes(2, "big") + chunk.to_bytes(2, "big") \
                       + len(chunk_data).to_bytes(2, "big") + chunk_data
            print(f"--> Sending: Chunk {chunk} to {client_addr}")
            self.sock.sendto(response, client_addr)
            sleep(.01)
        print("Transference complete")

    def connect(self):
        print("Peer started. Waiting for requests.")
        while True:
            packet, sender_addr = self.__receive_request()
            request_code = int.from_bytes(packet[:2], "big")
            if request_code == 1:  # Hello from client
                searched_chunks_id = self.__unpack_chunk_request(packet[2:])
                print(f"Client searching for {searched_chunks_id} at {sender_addr}")
                self.__send_query(searched_chunks_id, sender_addr)
                self.__send_chunk_info(searched_chunks_id, sender_addr)
            elif request_code == 4:  # Get from client
                requested_chunks_id = self.__unpack_chunk_request(packet[2:])
                print(f"Client requested {requested_chunks_id} at {sender_addr}")
                self.__send_response_chunks(requested_chunks_id, sender_addr)
            elif request_code == 2:  # Query from peer
                client_addr, ttl, searched_chunks_id = self.__unpack_query(packet)
                print(f"Received query: {client_addr}, {ttl}, {searched_chunks_id}")
                self.__send_query(searched_chunks_id, client_addr, ttl-1, sender_addr)
                self.__send_chunk_info(searched_chunks_id, client_addr)


if __name__ == "__main__":
    if len(sys.argv) < 4:
        usage("peer", sys.argv[0])

    local_addr = ('127.0.0.1', int(sys.argv[1]))
    local_chunks = decode_key_values_from_file(sys.argv[2])
    peers_connected = get_peers_connected_from_file(sys.argv[3:])

    peer = Peer(local_addr, local_chunks, peers_connected)
    peer.connect()
