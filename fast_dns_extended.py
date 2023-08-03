import dns.resolver
from dns.message import Message


def send_dns_query_by_addr(message: Message, addr: str) -> Message:
    response = dns.query.udp(message, addr)
    return response
