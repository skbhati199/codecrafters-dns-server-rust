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
    let id = u16::from_be_bytes([request[0], request[1]]);
    let flags = u16::from_be_bytes([request[2], request[3]]);
    let qdcount = u16::from_be_bytes([request[4], request[5]]);
    let opcode = (flags >> 11) & 0xF;
    let rd = flags & 0x100;  // Extract RD flag (bit 8)

    let response_flags = 0x8000 | (opcode << 11) | rd;  // QR = 1, keep original OPCODE and RD

    response.extend_from_slice(&id.to_be_bytes());
    response.extend_from_slice(&response_flags.to_be_bytes());
    response.extend_from_slice(&qdcount.to_be_bytes());
    response.extend_from_slice(&qdcount.to_be_bytes());  // ANCOUNT: same as QDCOUNT
    response.extend_from_slice(&[0x00, 0x00]);  // NSCOUNT: 0
    response.extend_from_slice(&[0x00, 0x00]);  // ARCOUNT: 0

    let (questions, _) = parse_questions(request, 12, qdcount as usize);

    // Add questions to response
    for question in &questions {
        response.extend_from_slice(question);
    }

    // Add answers to response
    for question in &questions {
        response.extend_from_slice(&[0xC0, 0x0C]);  // Pointer to the question name
        response.extend_from_slice(&[0x00, 0x01]);  // TYPE: A (1)
        response.extend_from_slice(&[0x00, 0x01]);  // CLASS: IN (1)
        response.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]);  // TTL: 60 seconds
        response.extend_from_slice(&[0x00, 0x04]);  // RDLENGTH: 4 bytes
        response.extend_from_slice(&[8, 8, 8, 8]);  // RDATA: 8.8.8.8 (example IP)
    }

    response
}

fn parse_questions(packet: &[u8], mut offset: usize, count: usize) -> (Vec<Vec<u8>>, usize) {
    let mut questions = Vec::new();

    for _ in 0..count {
        let (question, new_offset) = parse_name(packet, offset);
        offset = new_offset;

        // Add QTYPE and QCLASS
        let mut full_question = question;
        full_question.extend_from_slice(&packet[offset..offset + 4]);
        offset += 4;

        questions.push(full_question);
    }

    (questions, offset)
}

fn parse_name(packet: &[u8], mut offset: usize) -> (Vec<u8>, usize) {
    let mut name = Vec::new();
    let mut jumped = false;
    let mut max_jumps = 10;  // Prevent infinite loops
    let mut jump_offset = offset;

    loop {
        if max_jumps == 0 { break; }
        if offset >= packet.len() { break; }

        let len = packet[offset] as usize;
        if len & 0xC0 == 0xC0 {
            if !jumped {
                jump_offset = offset + 2;
            }
            if offset + 1 < packet.len() {
                offset = ((len & 0x3F) as usize) << 8 | packet[offset + 1] as usize;
                jumped = true;
                max_jumps -= 1;
                continue;
            } else {
                break;
            }
        } else if len > 0 {
            name.extend_from_slice(&packet[offset..offset + len + 1]);
            offset += len + 1;
        } else {
            name.push(0);
            offset += 1;
            break;
        }
    }

    if jumped {
        (name, jump_offset)
    } else {
        (name, offset)
    }
}