import sys


def usage(alias, file):
    if alias == "client":
        print("usage:", file, "<starting_peer> <chunks_list>")
    elif alias == "peer":
        print("usage:", file, "<local_port> <key-values-files_peer[id]> <ip1:port1>...<ipN:portN>")
    sys.exit(1)
