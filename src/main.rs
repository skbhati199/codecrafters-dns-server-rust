use std::net::UdpSocket;

fn main() {
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];
    
    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((_, source)) => {
                let response = create_dns_response();
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


fn create_dns_response() -> Vec<u8> {
    let mut response = Vec::new();

    // Header section (12 bytes)
    response.extend_from_slice(&[
        0x04, 0xD2, // ID: 1234
        0x80, 0x00, // Flags: QR = 1, everything else = 0
        0x00, 0x01, // QDCOUNT: 1
        0x00, 0x01, // ANCOUNT: 1 (updated)
        0x00, 0x00, // NSCOUNT: 0
        0x00, 0x00, // ARCOUNT: 0
    ]);

    // Question section
    // Name: codecrafters.io
    response.extend_from_slice(&[
        0x0c, b'c', b'o', b'd', b'e', b'c', b'r', b'a', b'f', b't', b'e', b'r', b's',
        0x02, b'i', b'o',
        0x00, // Null terminator
    ]);

    // Type: A (1)
    response.extend_from_slice(&[0x00, 0x01]);

    // Class: IN (1)
    response.extend_from_slice(&[0x00, 0x01]);

    // Answer section
    // Name: pointer to the domain name in the question section
    response.extend_from_slice(&[0xc0, 0x0c]); // Pointer to offset 12

    // Type: A (1)
    response.extend_from_slice(&[0x00, 0x01]);

    // Class: IN (1)
    response.extend_from_slice(&[0x00, 0x01]);

    // TTL: 60 seconds
    response.extend_from_slice(&[0x00, 0x00, 0x00, 0x3c]);

    // RDLENGTH: 4 (length of IPv4 address)
    response.extend_from_slice(&[0x00, 0x04]);

    // RDATA: IP address (8.8.8.8 in this example)
    response.extend_from_slice(&[0x08, 0x08, 0x08, 0x08]);

    response
}
