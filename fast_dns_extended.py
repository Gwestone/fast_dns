import socket
from typing import Tuple

import dns.resolver
from dns.message import Message


def send_query_to_dns(message: Message, addr: str) -> Message:
    response = dns.query.udp(message, addr)
    return response


def send_query_to_client(message: Message, server_socket: socket, client_address: Tuple[str, str]):
    # Send the bytearray to the specified IP and port
    server_socket.sendto(message.to_wire(), client_address)
