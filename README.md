# peer_to_peer_video_share

Client: python client.py 127.0.0.1:5001 5,6,7,8
Peer: python peer.py 5001 data/Key-values-files/key-values-files_peer1 127.0.0.1:5002 127.0.0.1:5003
python peer.py 5002 data/Key-values-files/key-values-files_peer2 127.0.0.1:5001 127.0.0.1:5003