from typing import List
from dns.message import Message
from fast_dns_message import remove_last_period


def check_if_blacklisted(decoded_dns_message: Message, blacklist: List[str]) -> bool:
    for item in blacklist:
        if remove_last_period(decoded_dns_message.question[0].name.to_text()) == item:
            return True
    return False
