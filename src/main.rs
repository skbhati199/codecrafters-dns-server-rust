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

    // Extract values from request header
    let id = u16::from_be_bytes([request[0], request[1]]);
    let flags = u16::from_be_bytes([request[2], request[3]]);
    let opcode = (flags >> 11) & 0xF;
    let rd = flags & 0x100;  // Extract RD flag (bit 8)

    // Construct response header
    let response_flags = if opcode == 0 {
        0x8000 | (opcode << 11) | rd  // QR = 1, keep original OPCODE and RD
    } else {
        0x8000 | (opcode << 11) | rd | 0x4  // Not implemented
    };

    response.extend_from_slice(&id.to_be_bytes());
    response.extend_from_slice(&response_flags.to_be_bytes());
    response.extend_from_slice(&[0x00, 0x01]);  // QDCOUNT: 1
    response.extend_from_slice(&[0x00, 0x01]);  // ANCOUNT: 1
    response.extend_from_slice(&[0x00, 0x00]);  // NSCOUNT: 0
    response.extend_from_slice(&[0x00, 0x00]);  // ARCOUNT: 0

    // Parse and copy question section
    let (question_section, domain_name) = parse_question_section(&request[12..]);
    response.extend_from_slice(&question_section);

    // Construct answer section
    response.extend_from_slice(&domain_name);  // NAME: pointer to the domain name
    response.extend_from_slice(&[0x00, 0x01]);  // TYPE: A (1)
    response.extend_from_slice(&[0x00, 0x01]);  // CLASS: IN (1)
    response.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]);  // TTL: 60 seconds
    response.extend_from_slice(&[0x00, 0x04]);  // RDLENGTH: 4 bytes
    response.extend_from_slice(&[8, 8, 8, 8]);  // RDATA: 8.8.8.8

    response
}

fn parse_question_section(question: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut parsed = Vec::new();
    let mut i = 0;
    let mut label_positions = Vec::new();

    while i < question.len() {
        let label_length = question[i] as usize;
        if label_length == 0 {
            parsed.push(0);
            i += 1;
            break;
        }
        label_positions.push(parsed.len() as u16);
        parsed.extend_from_slice(&question[i..i + label_length + 1]);
        i += label_length + 1;
    }

    // Add QTYPE and QCLASS
    parsed.extend_from_slice(&question[i..i + 4]);

    // Create domain name pointer
    let domain_name = vec![0xC0, 0x0C];  // Pointer to offset 12

    (parsed, domain_name)
}
