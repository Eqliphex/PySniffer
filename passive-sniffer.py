import socket
import struct

# Kig op på RAW_SOCKET
# Access point til rPi
# rdpcap
# gem med scapy
def main():

    host = socket.gethostbyname(socket.gethostname())
    print('IP: {}'.format(host))

    connection = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    connection.bind(host)

    connection.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    connection.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    while True:
        raw_data, addr = connection.recv(65536)

        dest_mac, src_mac, eth_proto, data = unpack_ethernet_frame(raw_data)

        print('\nEthernet Frame:')
        print('Destination MAC: {}, Source MAC: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))


def unpack_ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return (get_formatted_mac_address(dest_mac), get_formatted_mac_address(src_mac),
            socket.htons(proto), data[14:])


def get_formatted_mac_address(bytes_address):
    bytes_string_list = map('{:02x}'.format, bytes_address)
    formatted_string = ':'.join(bytes_string_list).upper()
    return formatted_string


def get_protocol(bytes_protocol):
    bytes_str = map('{:02x}'.format, bytes_protocol)
    protocol = ''.join(bytes_str).upper()
    return protocol


if __name__ == '__main__':
    main()
