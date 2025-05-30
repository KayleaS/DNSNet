use std::{num::NonZeroUsize, time::Instant};

use etherparse::{IpHeaders, UdpHeader};
use lru::LruCache;
use simple_dns::{Packet, rdata::RData};

use crate::bridge::Bridge;

#[derive(Eq, Hash, PartialEq)]
enum DnsCacheRecordType {
    A,
    AAAA,
}

#[derive(Debug, Clone)]
struct DnsRecord<'a> {
    packet: Packet<'a>,
    time_to_live: u64,
    creation_time: Instant,
}

struct Resolver<'a> {
    bridge: Bridge<Vec<u8>, Vec<u8>>,
    cache: LruCache<(String, DnsCacheRecordType), DnsRecord<'a>>,
}

impl <'a> Resolver<'a> {
    const CACHE_SIZE: NonZeroUsize = NonZeroUsize::new(100).unwrap();

    pub fn new() -> Self {
        Self {
            bridge: Bridge::new(),
            cache: LruCache::new(Self::CACHE_SIZE),
        }
    }

    pub fn request(
        &mut self,
        original_ip_packet_header: IpHeaders,
        original_udp_packet_header: UdpHeader,
        dns_payload: Packet,
        destination_address: Vec<u8>,
    ) {
        if let Some(mut cached_response) = self.get_cached_response(&dns_payload) {
            // TODO: Send response back
            return;
        }
    }

    pub fn respond(
        &mut self,
        original_ip_packet_header: IpHeaders,
        original_udp_packet_header: UdpHeader,
        response_packet: &'a [u8],
        destination_address: Vec<u8>,
    ) {
        self.cache_response(response_packet);
    }

    fn get_cached_response(&mut self, request_packet: &Packet) -> Option<Packet> {
        trace!(
            "get: Cache status - {}/{}",
            self.cache.len(),
            self.cache.cap()
        );

        let question = match request_packet.questions.first() {
            Some(value) => value,
            None => {
                error!("get_cached_response: Payload had no question! This should never happen.");
                return None;
            },
        };
        let host_name = question.qname.to_string();

        let responses = self.get_cached_responses(&host_name);
        match responses.0 {
            Some(mut ipv4_record) => {
                ipv4_record.set_id(request_packet.id());
                Some(ipv4_record)
            },
            None => {
                match responses.1 {
                    Some(mut ipv6_record) => {
                        ipv6_record.set_id(request_packet.id());
                        Some(ipv6_record)
                    },
                    None => None,
                }
            },
        }
    }

    fn get_cached_responses(&mut self, host_name: &str) -> (Option<Packet>, Option<Packet>) {
        let ipv4_key = &(host_name.to_string(), DnsCacheRecordType::A);
        let ipv4_record = match self.cache.get(ipv4_key) {
            Some(record) => {
                let record_age_seconds = Instant::now()
                    .duration_since(record.creation_time)
                    .as_secs();
                if record_age_seconds > record.time_to_live {
                    debug!("get: Popping old DNS record for {host_name}");
                    self.cache.pop(ipv4_key);
                } else {
                    debug!("get: Cache hit for {host_name}");
                    Some(record.packet.clone());
                }
                None
            },
            None => None,
        };

        if ipv4_record.is_some() {
            return (ipv4_record, None);
        }

        let ipv6_key = &(host_name.to_string(), DnsCacheRecordType::AAAA);
        let ipv6_record = match self.cache.get(ipv6_key) {
            Some(record) => {
                let record_age_seconds = Instant::now()
                    .duration_since(record.creation_time)
                    .as_secs();
                if record_age_seconds > record.time_to_live {
                    debug!("get: Popping old DNS record for {host_name}");
                    self.cache.pop(ipv6_key);
                } else {
                    debug!("get: Cache hit for {host_name}");
                    Some(record.packet.clone());
                }
                None
            },
            None => None,
        };

        return (ipv4_record, ipv6_record);
    }

    fn cache_response(&mut self, response_packet: &'a [u8]) {
        trace!(
            "cache_response: Cache status - {}/{}",
            self.cache.len(),
            self.cache.cap()
        );
        let packet = match Packet::parse(response_packet) {
            Ok(value) => value,
            Err(error) => {
                warn!("cache_response: Failed to parse response packet! - {:?}", error);
                return;
            }
        };

        for record in &packet.additional_records {
            match &record.rdata {
                RData::A(a) => todo!(),
                RData::AAAA(aaaa) => todo!(),
                RData::NS(ns) => todo!(),
                RData::MD(md) => todo!(),
                RData::CNAME(cname) => todo!(),
                RData::MB(mb) => todo!(),
                RData::MG(mg) => todo!(),
                RData::MR(mr) => todo!(),
                RData::PTR(ptr) => todo!(),
                RData::MF(mf) => todo!(),
                RData::HINFO(hinfo) => todo!(),
                RData::MINFO(minfo) => todo!(),
                RData::MX(mx) => todo!(),
                RData::TXT(txt) => todo!(),
                RData::SOA(soa) => todo!(),
                RData::WKS(wks) => todo!(),
                RData::SRV(srv) => todo!(),
                RData::RP(rp) => todo!(),
                RData::AFSDB(afsdb) => todo!(),
                RData::ISDN(isdn) => todo!(),
                RData::RouteThrough(route_through) => todo!(),
                RData::NAPTR(naptr) => todo!(),
                RData::NSAP(nsap) => todo!(),
                RData::NSAP_PTR(nsap_ptr) => todo!(),
                RData::LOC(loc) => todo!(),
                RData::OPT(opt) => todo!(),
                RData::CAA(caa) => todo!(),
                RData::SVCB(svcb) => todo!(),
                RData::HTTPS(https) => todo!(),
                RData::EUI48(eui48) => todo!(),
                RData::EUI64(eui64) => todo!(),
                RData::CERT(cert) => todo!(),
                RData::ZONEMD(zonemd) => todo!(),
                RData::KX(kx) => todo!(),
                RData::IPSECKEY(ipseckey) => todo!(),
                RData::DNSKEY(dnskey) => todo!(),
                RData::RRSIG(rrsig) => todo!(),
                RData::DS(ds) => todo!(),
                RData::NSEC(nsec) => todo!(),
                RData::DHCID(dhcid) => todo!(),
                RData::NULL(_, null) => todo!(),
                RData::Empty(_) => todo!(),
            }
        }

        let question = match packet.questions.first() {
            Some(value) => value,
            None => {
                warn!("cache_response: No answer found in response packet!");
                return;
            }
        };
        let host_name = question.qname.to_string();

        let answer = match packet.answers.first() {
            Some(value) => value,
            None => {
                warn!("cache_response: No answer found in response packet!");
                return;
            }
        };

        let time_to_live = answer.ttl as u64;
        let record_type = match answer.rdata {
            RData::A(_) => DnsCacheRecordType::A,
            RData::AAAA(_) => DnsCacheRecordType::AAAA,
            _ => {
                debug!("cache_response: Invalid RData response type!");
                return;
            }
        };

        let new_record = DnsRecord {
            packet,
            time_to_live,
            creation_time: Instant::now(),
        };
        debug!("cache_response: New cache entry for {}", host_name);
        self.cache.put((host_name, record_type), new_record);

        // TODO: Cache authoritative nameserver addresses
    }

    fn create_new_response() {}
}
