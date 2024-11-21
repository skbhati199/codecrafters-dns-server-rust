use anyhow::Result;
use dns_starter_rust::{DnsMessage, Question, ResourceRecord, QClass, QType};
use std::net::UdpSocket;

fn main() -> Result<()> {
    println!("Logs from your program will appear here!");
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];
    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {}", size, source);
                let mut msg = DnsMessage::try_from_bytes(buf)?;
                if !msg.header().is_qr() {
                    msg.header_mut().set_resp();
                }
                if msg.header().opcode() != 0 {
                    msg.header_mut()
                        .set_rcode(dns_starter_rust::ResponseCode::NotImplemented);
                }

                // Process all questions
                let question_count = msg.header().qdcount();
                for i in 0..question_count {
                    let q = msg.get_question(i as usize);
                    let decompressed_q = decompress_question(&q, &buf)?;
                    msg.push_question(decompressed_q.clone());
                    let answ = answer_stub(&decompressed_q)?;
                    msg.push_answer(answ);
                }

                // Remove the original compressed questions
                for _ in 0..question_count {
                    msg.questions_mut().remove(0);
                }

                let resp = msg.to_bytes();
                let n = udp_socket
                    .send_to(&resp, source)
                    .expect("Failed to send response");
                println!("Wrote {n} bytes to {source}");
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
    Ok(())
}

fn decompress_question(q: &Question, buf: &[u8]) -> Result<Question> {
    let mut decompressed_labels = Vec::new();
    let mut offset = q.offset();

    loop {
        let label_length = buf[offset] as usize;
        if label_length == 0 {
            break;
        }

        if label_length & 0xC0 == 0xC0 {
            // Compressed label pointer
            let pointer = ((buf[offset] as u16 & 0x3F) << 8) | buf[offset + 1] as u16;
            offset = pointer as usize;
        } else {
            // Uncompressed label
            let label = String::from_utf8(buf[offset + 1..offset + 1 + label_length].to_vec())?;
            decompressed_labels.push(label);
            offset += label_length + 1;
        }
    }

    Ok(Question::new(
        decompressed_labels,
        q.qtype().clone(),
        q.qclass().clone(),
    ))
}

fn answer_stub(q: &Question) -> Result<ResourceRecord> {
    let name = q.get_labels()?;
    let data = vec![192, 0, 2, 0];
    Ok(ResourceRecord::A {
        name,
        class: QClass::IN,
        ttl: 65,
        len: data.len() as u16,
        data,
    })
}

