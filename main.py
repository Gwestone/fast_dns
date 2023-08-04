import select
import socket
import dns.message

from fast_dns_blacklist import check_if_blacklisted
from fast_dns_config import load_config
from fast_dns_extended import send_query_to_dns, send_query_to_client
from fast_dns_message import print_query, remove_last_period, print_response, print_bytestring

config = load_config('config.json')

# Create a UDP socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Bind the socket to a specific address and port
server_address = ('127.0.0.1', config["port"])
server_socket.bind(server_address)

print(f"Running DNS proxy server on {server_address[0]}:{server_address[1]}")

# Create an epoll object
epoll = select.epoll()

# Register the server socket with EPOLLIN event (data available to read)
epoll.register(server_socket.fileno(), select.EPOLLIN)

try:
    connections = {}
    while True:
        events = epoll.poll()
        for fileno, event in events:
            if fileno == server_socket.fileno():
                # New UDP packet received on the server socket
                data, client_address = server_socket.recvfrom(1024)
                print_bytestring(data, client_address)

                decoded_dns_message = dns.message.from_wire(data)
                print_query(decoded_dns_message)

                if check_if_blacklisted(decoded_dns_message, config["blacklist"]):
                    print(f"Blacklisted domain: {remove_last_period(decoded_dns_message.question[0].name.to_text())}")
                    print(config["errors"]["blacklist"])
                    decoded_dns_message.set_rcode(dns.rcode.REFUSED)
                    send_query_to_client(decoded_dns_message, server_socket, client_address)

                else:
                    print(f"Redirecting request to DNS server: {config['redirect']}")
                    resource = send_query_to_dns(decoded_dns_message, config["redirect"])
                    print_response(resource)
                    print_bytestring(resource.to_wire(), client_address)

                    send_query_to_client(resource, server_socket, client_address)

finally:
    # Close the server socket and clean up
    epoll.unregister(server_socket.fileno())
    epoll.close()
    server_socket.close()
    