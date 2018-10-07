import socket
import struct


def main():
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = connection.recv(65536)
        dest_mac, src_mac, eth_proto, data = unpack_ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print('Destination: {}, Source {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))


def unpack_ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return (get_formatted_mac_address(dest_mac), get_formatted_mac_address(src_mac),
            socket.htons(proto), data[14:])


def get_formatted_mac_address(bytes_address):
    bytes_string_list = map('{:02x}'.format, bytes_address)
    formatted_string = ':'.join(bytes_string_list).upper()
    return formatted_string


if __name__ == '__main__':
    main()
