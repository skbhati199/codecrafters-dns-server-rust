use std::net::UdpSocket;

fn main() {
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];
    
    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((_, source)) => {
                let response = create_dns_header();
                udp_socket
                    .send_to(&response, source)
                    .expect("Failed to send response");
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}

fn create_dns_header() -> [u8; 12] {
    let mut header = [0u8; 12];

    // Packet Identifier (ID): 16 bits (1234 in big-endian)
    header[0] = 0x04;
    header[1] = 0xD2;

    // Flags: 16 bits
    // QR (1 bit) | OPCODE (4 bits) | AA (1 bit) | TC (1 bit) | RD (1 bit) | RA (1 bit) | Z (3 bits) | RCODE (4 bits)
    // 1000 0000 | 0000 0000
    header[2] = 0x80;
    header[3] = 0x00;

    // Question Count (QDCOUNT): 16 bits (0)
    header[4] = 0x00;
    header[5] = 0x00;

    // Answer Record Count (ANCOUNT): 16 bits (0)
    header[6] = 0x00;
    header[7] = 0x00;

    // Authority Record Count (NSCOUNT): 16 bits (0)
    header[8] = 0x00;
    header[9] = 0x00;

    // Additional Record Count (ARCOUNT): 16 bits (0)
    header[10] = 0x00;
    header[11] = 0x00;

    header
}