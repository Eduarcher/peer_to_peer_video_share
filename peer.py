import socket
from libs.common import *
from time import sleep
buffer_size = 2048


def decode_key_values_file(addr):
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


class Peer:
    def __init__(self, local_addr, local_chunks, ip_version=4):
        self.ip_version = socket.AF_INET if ip_version == 4 else socket.AF_INET6
        self.sock = socket.socket(self.ip_version, socket.SOCK_DGRAM)
        self.local_addr = local_addr
        self.sock.bind(self.local_addr)
        self.local_chunks = local_chunks

    def __get_available_chunks_ids(self, chunks):
        return sorted(list(set(self.local_chunks).intersection(chunks)))

    def __chunks_ids_to_bytes(self, chunks):
        return b"".join([chunk.to_bytes(2, "big") for chunk in chunks])

    def __unpack_chunk_request(self, packet):
        # sourcery skip: inline-immediately-returned-variable
        quantity_chunk = int.from_bytes(packet[2:4], "big")
        chunks_id_list = [int.from_bytes(packet[4 + (2 * x):6 + (2 * x)], "big")
                          for x in range(quantity_chunk)]
        return chunks_id_list

    def __receive_request(self):
        packet, addr = self.sock.recvfrom(buffer_size)
        print(f"<-- Received: {packet} from {addr}")
        return packet, addr

    def __receive_hello(self):
        packet, client_addr = self.__receive_request()
        if int.from_bytes(packet[:2], "big") != 1:
            self.__receive_hello()
        else:
            chunks_id_list = self.__unpack_chunk_request(packet)
            return chunks_id_list, client_addr

    def __send_chunk_info(self, chunks_list, client_addr):
        available_chunks = self.__get_available_chunks_ids(chunks_list)
        response = (3).to_bytes(2, "big") + len(available_chunks).to_bytes(2, "big") \
                    + self.__chunks_ids_to_bytes(available_chunks)
        print(f"--> Sending: {response} to {client_addr}")
        self.sock.sendto(response, client_addr)

    def __receive_get_chunks(self):
        packet, client_addr = self.__receive_request()
        if int.from_bytes(packet[:2], "big") != 4:
            self.__receive_get_chunks()
        else:
            chunks_id_list = self.__unpack_chunk_request(packet)
            return chunks_id_list, client_addr

    def __send_response_chunks(self, chunks, client_addr):
        for chunk in chunks:
            chunk_data = open("data/" + self.local_chunks[chunk], "rb").read(1024)
            response = (5).to_bytes(2, "big") + chunk.to_bytes(2, "big") \
                       + len(chunk_data).to_bytes(2, "big") + chunk_data
            print(f"--> Sending: Chunk {chunk} to {client_addr}")
            self.sock.sendto(response, client_addr)
            sleep(.01)

    def connect(self):
        print("Peer started. Waiting for requests.")
        chunks_id, client_addr = self.__receive_hello()
        print(f"Client searching for {chunks_id} from {client_addr}")
        self.__send_chunk_info(chunks_id, client_addr)
        requested_chunks_id, client_addr = self.__receive_get_chunks()
        print(f"Client requested {requested_chunks_id} at {client_addr}")
        self.__send_response_chunks(requested_chunks_id, client_addr)


if __name__ == "__main__":
    if len(sys.argv) < 4:
        usage("peer", sys.argv[0])

    local_addr = ('127.0.0.1', int(sys.argv[1]))
    local_chunks = decode_key_values_file(sys.argv[2])

    peer = Peer(local_addr, local_chunks)
    peer.connect()
