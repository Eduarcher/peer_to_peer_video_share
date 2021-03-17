import socket
from pathlib import Path
import constants as const
from libs.common import *
from libs.testing_tools import *

BUFFER_SIZE = const.buffer_size
debug = const.debug_mode


class Client:
    """
    Main client class for handling the file transference to the server
    """
    def __init__(self, local_addr, starting_peer_addr, chunks,
                 ip_version=4, log_file="output"):
        self.local_addr = local_addr
        self.starting_peer_addr = starting_peer_addr
        self.ip_version = ip_version
        self.target_chunks = chunks
        self.quantity_chunks = len(chunks)
        self.log_file = self.__init_folder_and_file(const.log_output_folder,
                                                    f"{log_file}{local_addr[0]}.log")

    def __chunks_ids_to_bytes(self, chunks=None):
        chunks = self.target_chunks if not chunks else chunks
        return b"".join([chunk.to_bytes(2, 'big') for chunk in chunks])

    def __init_folder_and_file(self, folder, file, write_bytes=False):
        write_method = "wb" if write_bytes else "w"
        Path(folder).mkdir(parents=True, exist_ok=True)
        return open(f"{folder}{file}", write_method)

    def __receive_request(self, sock):
        packet, addr = sock.recvfrom(BUFFER_SIZE)
        print(f"<-- Received: {packet[:min(20, len(packet))]}(Showing 20 bytes) from {addr}")
        return packet, addr

    def __request_hello(self, sock):
        request = (1).to_bytes(2, 'big') + self.quantity_chunks.to_bytes(2, 'big') \
                  + self.__chunks_ids_to_bytes()
        print(f"--> Sending: {request} to {self.starting_peer_addr}")
        sock.sendto(request, self.starting_peer_addr)

    def __receive_chunks_info(self, packet, addr):
        quantity_chunk = int.from_bytes(packet[2:4], 'big')
        chunks_id_list = [int.from_bytes(packet[4 + (2 * x):6 + (2 * x)], 'big')
                          for x in range(quantity_chunk)]
        return chunks_id_list, addr

    def __request_get_chunks(self, sock, chunks, addr):
        request_chunks = []
        for chunk in chunks:
            if chunk in self.target_chunks:
                request_chunks.append(chunk)
                self.target_chunks.remove(chunk)
        if request_chunks:
            request = (4).to_bytes(2, 'big') + len(request_chunks).to_bytes(2, 'big') \
                      + self.__chunks_ids_to_bytes(request_chunks)
            print(f"--> Sending: {request} to {addr}")
            sock.sendto(request, addr)
        return request_chunks

    def __receive_chunks_response(self, packet, requested, peer_addr):
        id_chunk = int.from_bytes(packet[2:4], 'big')
        if id_chunk in requested:
            size_chunk = int.from_bytes(packet[4:6], 'big')
            chunk_data = packet[6:6+size_chunk]
            output_file = self.__init_folder_and_file(const.file_output_folder,
                   f"{const.output_chunks_filename}"
                   f"{id_chunk}{const.output_chunks_format}", True)
            output_file.write(chunk_data)
            self.log_file.write(f"{peer_addr[0]}:{peer_addr[1]} - {id_chunk}\n")
            requested.remove(id_chunk)
        return requested

    def connect(self):
        sock_ip_version = socket.AF_INET if self.ip_version == 4 else socket.AF_INET6
        with socket.socket(sock_ip_version, socket.SOCK_DGRAM) as sock:
            sock.bind(self.local_addr)
            self.__request_hello(sock)
            remaining_packets = self.target_chunks.copy()
            while True:
                packet, addr = self.__receive_request(sock)
                packet_code = int.from_bytes(packet[:2], 'big')
                if len(packet) == 0:
                    print("Timeout. Transference cancelled.")  # TODO criar timeout
                    return -1
                if packet_code == 3:
                    available_chunks, peer_addr = self.__receive_chunks_info(packet, addr)
                    print(f"Available chunks: {available_chunks} at {peer_addr}")
                    self.__request_get_chunks(sock, available_chunks, peer_addr)
                if packet_code == 5:
                    remaining_packets = self.__receive_chunks_response(packet, remaining_packets, peer_addr)
                if len(remaining_packets) == 0:
                    print("Transference complete.")
                    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        usage("client", sys.argv[0])

    # Define variables and process arguments
    local_addr = const.client_addr
    peer_addr_str = sys.argv[1].split(":")
    starting_peer_addr, chunks = (peer_addr_str[0], int(peer_addr_str[1])), \
                                  list(map(int, sys.argv[2].split(",")))

    # Delete output files if in debug mode
    if debug:
        delete_files(const.file_output_folder)

    # Create Client object and connect
    client = Client(local_addr, starting_peer_addr, chunks)
    client.connect()
