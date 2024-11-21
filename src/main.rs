use anyhow::Result;
use dns_starter_rust::DnsMessage;
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
                // let q = msg.get_question(0);
                // let answ = answer_stub(q)?;
                // msg.push_answer(answ);
                for i in 0..msg.header().qdcount() {
                    let q = msg.get_question(i as usize);
                    let answ = answer_stub(q)?;
                    msg.push_answer(answ);
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
// Fill out an answer based on a question, used as a stub until we can actually
// resolve names
fn answer_stub(
    q: &dns_starter_rust::Question,
) -> Result<dns_starter_rust::ResourceRecord, anyhow::Error> {
    use dns_starter_rust::QClass;
    // Why String? Because I expect it will be easier to work with for searches
    let name = q.get_labels()?;
    let data = vec![192, 0, 2, 0];
    Ok(dns_starter_rust::ResourceRecord::A {
        name,
        class: QClass::IN,
        ttl: 65,
        len: data.len() as u16,
        data,
    })
}