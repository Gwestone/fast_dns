from dns.message import Message


def print_query(message: Message):
    print("-" * 20)
    print("Decoded query: ")
    print(f"DNS Request ID: {message.id}")
    print(f"DNS Request Opcode: {message.opcode()}")
    print(f"DNS Request RCode: {message.rcode()}")
    print(f"DNS Request Flags: {message.flags}")

    print(f"DNS Request Question:", end=" ")
    for item in message.question:
        print(remove_last_period(item.name.to_text()), end=" ")

    print(f"\nDNS Request Answer: {message.answer}")
    print(f"DNS Request Authority: {message.authority}")
    print(f"DNS Request Additional: {message.additional}")
    print("-" * 20)

def print_response(message: Message):
    print("-" * 20)
    print("Decoded response: ")
    print(f"DNS Request ID: {message.id}")
    print(f"DNS Request Opcode: {message.opcode()}")
    print(f"DNS Request RCode: {message.rcode()}")
    print(f"DNS Request Flags: {message.flags}")

    print(f"DNS Request Question:", end=" ")
    for item in message.question:
        print(remove_last_period(item.name.to_text()), end=" ")

    print(f"\nDNS Request Answer: {message.answer}")
    print(f"DNS Request Authority: {message.authority}")
    print(f"DNS Request Additional: {message.additional}")
    print("-" * 20)


def remove_last_period(input_string: str) -> str:
    if input_string.endswith("."):
        return input_string[:-1]
    else:
        return input_string
