mod utils;
use std::{fmt::Debug, net::UdpSocket};
fn main() {
    let addr = "127.0.0.1:2053";
    let udp_socket = UdpSocket::bind(addr).expect("Failed to bind to address");
    println!("Listening on udp://{addr}");
    let mut buf = [0; 512];
    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                let mut req = bytes::Bytes::copy_from_slice(&buf[..size]);
                println!("Received {} bytes from {}", size, source);
                println!("Bytes: {:02X?}", req);
                let req_header = Header::read_from(&mut req);
                let req_question = Question::read_from(&mut req);
                println!("req_header: {:?}", &req_header);
                println!("req_question: {}", &req_question);
                let mut res = bytes::BytesMut::new();
                let res_header = Header {
                    id: req_header.id,
                    opcode: req_header.opcode,
                    rd: req_header.rd,
                    rcode: if req_header.opcode == 0 { 0 } else { 4 },
                    qr: 1,
                    qdcount: 1,
                    ancount: 1,
                    ..Default::default()
                };
                let res_question = Question {
                    name: [(*b"codecrafters").into(), (*b"io").into()].into(),
                    name: req_question.name,
                    qtype: QuestionType::A,
                    class: QuestionClass::IN,
                };
                let res_answer = Answer {
                    question: res_question.clone(),
                    ttl: 60,
                    data: vec![8, 8, 8, 8].into(),
                };
                println!("res_header: {:?}", &res_header);
                println!("res_question: {}", &res_answer);
                Header::write_to(res_header, &mut res);
                Question::write_to(res_question, &mut res);
                Answer::write_to(res_answer, &mut res);
                println!("res {:02X?}", res);
                udp_socket
                    .send_to(&res, source)
                    .expect("Failed to send response");
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}
#[derive(Debug, Default, Clone)]
struct Header {
    id: u16,
    qr: u8,
    opcode: u8,
    aa: u8,
    tc: u8,
    rd: u8,
    ra: u8,
    z: u8,
    rcode: u8,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
}
impl Header {
    fn read_from(buf: &mut bytes::Bytes) -> Self {
        use bytes::Buf;
        let id = buf.get_u16();
        let (qr, opcode, aa, tc, rd) = unpack_bits!(buf.get_u8(), 1, 4, 1, 1, 1);
        let (ra, z, rcode) = unpack_bits!(buf.get_u8(), 1, 3, 4);
        let qdcount = buf.get_u16();
        let ancount = buf.get_u16();
        let nscount = buf.get_u16();
        let arcount = buf.get_u16();
        Self {
            id,
            qr,
            opcode,
            aa,
            tc,
            rd,
            ra,
            z,
            rcode,
            qdcount,
            ancount,
            nscount,
            arcount,
        }
    }
    fn write_to(self, buf: &mut bytes::BytesMut) {
        use bytes::BufMut;
        buf.put_u16(self.id);
        buf.put_u8(pack_bits!(
            (self.qr, 1),
            (self.opcode, 4),
            (self.aa, 1),
            (self.tc, 1),
            (self.rd, 1)
        ));
        buf.put_u8(pack_bits!((self.ra, 1), (self.z, 3), (self.rcode, 4)));
        buf.put_u16(self.qdcount);
        buf.put_u16(self.ancount);
        buf.put_u16(self.nscount);
        buf.put_u16(self.arcount);
    }
}
#[derive(Debug, Clone)]
struct Question {
    name: Box<[Box<[u8]>]>,
    qtype: QuestionType,
    class: QuestionClass,
}
#[derive(Debug, Clone)]
struct Answer {
    question: Question,
    ttl: u32,
    data: Box<[u8]>,
}
impl Question {
    fn read_from(buf: &mut bytes::Bytes) -> Self {
        use bytes::Buf;
        let mut name = Vec::new();
        let mut length = buf.get_u8();
        while length != 0 {
            name.push((0..length).map(|_| buf.get_u8()).collect());
            length = buf.get_u8();
        }
        Self {
            name: name.into(),
            qtype: buf.get_u16().into(),
            class: buf.get_u16().into(),
        }
    }
    fn write_to(self, buf: &mut bytes::BytesMut) {
        use bytes::BufMut;
        for label in self.name.iter() {
            buf.put_u8(label.len() as u8);
            label.iter().for_each(|b| {
                buf.put_u8(*b);
            })
        }
        buf.put_u8(0);
        buf.put_u16(self.qtype.into());
        buf.put_u16(self.class.into());
    }
}
impl Answer {
    #[allow(dead_code)]
    fn read_from(buf: &mut bytes::Bytes) -> Self {
        use bytes::Buf;
        let question = Question::read_from(buf);
        let ttl = buf.get_u32();
        let length = buf.get_u16();
        let data = (0..length).map(|_| buf.get_u8()).collect::<Vec<_>>();
        Self {
            question,
            ttl,
            data: data.into(),
        }
    }
    fn write_to(self, buf: &mut bytes::BytesMut) {
        use bytes::BufMut;
        self.question.write_to(buf);
        buf.put_u32(self.ttl);
        buf.put_u16(self.data.len() as u16);
        self.data.iter().for_each(|&d| buf.put_u8(d));
    }
}
define_numeric_enum! {
    enum QuestionType<u16> {
        A = 1,      // a host address
        NS = 2,     // an authoritative name server
        MD = 3,     // a mail destination (Obsolete - use MX)
        MF = 4,     // a mail forwarder (Obsolete - use MX)
        CNAME = 5,  // the canonical name for an alias
        SOA = 6,    // marks the start of a zone of authority
        MB = 7,     // a mailbox domain name (EXPERIMENTAL)
        MG = 8,     // a mail group member (EXPERIMENTAL)
        MR = 9,     // a mail rename domain name (EXPERIMENTAL)
        NULL = 10,  // a null RR (EXPERIMENTAL)
        WKS = 11,   // a well known service description
        PTR = 12,   // a domain name pointer
        HINFO = 13, // host information
        MINFO = 14, // mailbox or mail list information
        MX = 15,    // mail exchange
        TXT = 16    // text strings
    }
}
define_numeric_enum! {
    enum QuestionClass<u16> {
        IN = 1,     // the Internet
        CS = 2,     // the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
        CH = 3,     // the CHAOS class
        HS = 4,     // Hesiod [Dyer 87]
    }
}
impl std::fmt::Display for Question {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = self
            .name
            .iter()
            .map(|n| bytes::Bytes::from(n.clone()))
            .collect::<Vec<_>>();
        write!(
            f,
            "Question ({name:?}, {qtype:?}, {class:?})",
            name = name,
            qtype = self.qtype,
            class = self.class
        )
    }
}
impl std::fmt::Display for Answer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let data = bytes::Bytes::from(self.data.clone());
        write!(
            f,
            "Answer ({}, ttl={}, data={:?})",
            self.question, self.ttl, data
        )
    }
}
#[test]
fn testparse() {
    let buf =
        b"\xa8\xb8\x01 \0\x01\0\0\0\0\0\x01\x07example\x03com\0\0\x01\0\x01\0\0)\x10\0\0\0\0\0\0\0";
    let mut req = bytes::Bytes::copy_from_slice(buf);
    let mut res = bytes::BytesMut::new();
    Header::read_from(&mut req).write_to(&mut res);
    Question::read_from(&mut req).write_to(&mut res);
    assert_eq!(&buf[..29], &res.to_vec()[..]);
}