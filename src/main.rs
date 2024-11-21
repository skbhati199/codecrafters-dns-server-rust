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
    let qdcount = u16::from_be_bytes([request[4], request[5]]);
    let opcode = (flags >> 11) & 0xF;
    let rd = flags & 0x100;  // Extract RD flag (bit 8)

    // Construct response header
    let response_flags = if opcode == 0 {
        0x8000 | (opcode << 11) | rd  // QR = 1, keep original OPCODE and RD
    } else {
        0x8000 | (opcode << 11) | rd | 0x4  // Not implemented
    };

    response.extend_from_slice(&id.to_be_bytes());  // Use the same ID as the request
    response.extend_from_slice(&response_flags.to_be_bytes());
    response.extend_from_slice(&qdcount.to_be_bytes());  // QDCOUNT: same as request
    response.extend_from_slice(&qdcount.to_be_bytes());  // ANCOUNT: same as QDCOUNT
    response.extend_from_slice(&[0x00, 0x00]);  // NSCOUNT: 0
    response.extend_from_slice(&[0x00, 0x00]);  // ARCOUNT: 0

    // Parse questions and construct response
    let mut offset = 12;  // Start after header
    let mut questions = Vec::new();

    for _ in 0..qdcount {
        let (question, new_offset) = parse_question(request, offset);
        questions.push(question);
        offset = new_offset;
    }

    // Add questions to response
    for question in &questions {
        response.extend_from_slice(question);
    }

    // Add answers to response
    for question in &questions {
        response.extend_from_slice(&question[..question.len() - 4]);  // Domain name
        response.extend_from_slice(&[0x00, 0x01]);  // TYPE: A (1)
        response.extend_from_slice(&[0x00, 0x01]);  // CLASS: IN (1)
        response.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]);  // TTL: 60 seconds
        response.extend_from_slice(&[0x00, 0x04]);  // RDLENGTH: 4 bytes
        response.extend_from_slice(&[8, 8, 8, 8]);  // RDATA: 8.8.8.8 (example IP)
    }

    response
}

fn parse_question(packet: &[u8], mut offset: usize) -> (Vec<u8>, usize) {
    let mut question = Vec::new();
    let mut is_pointer = false;

    loop {
        let length = packet[offset] as usize;
        if length == 0 {
            if !is_pointer {
                question.push(0);
            }
            offset += 1;
            break;
        } else if length & 0xC0 == 0xC0 {
            if !is_pointer {
                let pointer = u16::from_be_bytes([packet[offset] & 0x3F, packet[offset + 1]]);
                let (pointed_part, _) = parse_question(packet, pointer as usize);
                question.extend_from_slice(&pointed_part[..pointed_part.len() - 1]);  // Exclude null terminator
                offset += 2;
                is_pointer = true;
            } else {
                break;
            }
        } else {
            question.extend_from_slice(&packet[offset..offset + length + 1]);
            offset += length + 1;
        }
    }

    // Add QTYPE and QCLASS
    question.extend_from_slice(&packet[offset..offset + 4]);
    offset += 4;

    (question, offset)
}
