use std::net::UdpSocket;

fn main() {
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];
    
    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                if size >= 12 {  // Ensure we have at least the header
                    let response = create_dns_response(&buf[..size]);
                    udp_socket
                        .send_to(&response, source)
                        .expect("Failed to send response");
                }
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}


fn create_dns_response(request: &[u8]) -> Vec<u8> {
    let mut response = Vec::with_capacity(512);

    // Extract values from request
    let id = u16::from_be_bytes([request[0], request[1]]);
    let flags = u16::from_be_bytes([request[2], request[3]]);
    let opcode = (flags >> 11) & 0xF;
    let rd = flags & 0x1;

    // Construct response header
    let response_flags = if opcode == 0 {
        0x8000 | (opcode << 11) | (rd & 0x1)
    } else {
        0x8000 | (opcode << 11) | (rd & 0x1) | 0x4  // Not implemented
    };

    response.extend_from_slice(&id.to_be_bytes());
    response.extend_from_slice(&response_flags.to_be_bytes());
    response.extend_from_slice(&[0x00, 0x01]);  // QDCOUNT: 1
    response.extend_from_slice(&[0x00, 0x01]);  // ANCOUNT: 1
    response.extend_from_slice(&[0x00, 0x00]);  // NSCOUNT: 0
    response.extend_from_slice(&[0x00, 0x00]);  // ARCOUNT: 0

    // Question section (copy from request)
    let question_start = 12;
    let question_end = question_start + find_question_end(&request[question_start..]);
    response.extend_from_slice(&request[question_start..question_end]);

    // Answer section (simplified, just to keep the packet valid)
    response.extend_from_slice(&[0xC0, 0x0C]);  // Pointer to domain name
    response.extend_from_slice(&[0x00, 0x01]);  // Type: A
    response.extend_from_slice(&[0x00, 0x01]);  // Class: IN
    response.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]);  // TTL: 60 seconds
    response.extend_from_slice(&[0x00, 0x04]);  // RDLENGTH: 4 bytes
    response.extend_from_slice(&[127, 0, 0, 1]);  // IP: 127.0.0.1

    response
}

fn find_question_end(question: &[u8]) -> usize {
    let mut i = 0;
    while i < question.len() {
        if question[i] == 0 {
            return i + 5;  // null byte + QTYPE (2 bytes) + QCLASS (2 bytes)
        }
        i += question[i] as usize + 1;
    }
    question.len()
}