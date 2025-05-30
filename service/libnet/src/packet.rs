/* Copyright (C) 2025 Charles Lombardo <clombardo169@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

use etherparse::{
    IpHeaders, IpNumber, IpPayloadSlice, Ipv4Header, Ipv6FlowLabel, Ipv6Header, PacketBuilder,
    PacketBuilderStep, UdpSlice, ip_number,
};

/// Basic abstraction over a packet that lets us get a slice of a IPv4 or IPv6 header or payload
/// without doing extra allocations
#[derive(Debug)]
pub struct GenericIpPacket<'a> {
    header: IpHeaders,
    payload: IpPayloadSlice<'a>,
}

impl<'a> GenericIpPacket<'a> {
    /// Creates a new GenericIpPacket from a raw IP packet byte array
    pub fn new(ip_packet_slice: &'a [u8]) -> Option<Self> {
        match IpHeaders::from_slice(ip_packet_slice) {
            Ok((header, payload)) => Some(Self { header, payload }),
            Err(error) => {
                error!("new: Failed to parse IP packet slice! - {:?}", error);
                None
            }
        }
    }

    /// Gets a slice of the destination address from the packet header
    pub fn get_destination_address(&self) -> Option<Vec<u8>> {
        match &self.header {
            IpHeaders::Ipv4(ipv4_header, _) => Some(ipv4_header.destination.to_vec()),
            IpHeaders::Ipv6(ipv6_header, _) => Some(ipv6_header.destination.to_vec()),
        }
    }

    /// Gets a slice of the UDP payload from the packet
    pub fn get_udp_packet(&self) -> Option<UdpSlice> {
        match UdpSlice::from_slice(&self.payload.payload) {
            Ok(slice) => Some(slice),
            Err(error) => {
                error!(
                    "get_udp_packet: Failed to create UdpSlice from IP payload! - {:?}",
                    error
                );
                None
            }
        }
    }
}

fn build_ipv4_packet_with_udp_payload(
    source_address: &[u8; 4],
    source_port: u16,
    destination_address: &[u8; 4],
    destination_port: u16,
    time_to_live: u8,
    identification: u16,
    udp_payload: &[u8],
) -> Option<Vec<u8>> {
    let mut header = match Ipv4Header::new(
        udp_payload.len() as u16,
        time_to_live,
        ip_number::UDP,
        *source_address,
        *destination_address,
    ) {
        Ok(value) => value,
        Err(error) => {
            error!(
                "build_packet_v4: Failed to create Ipv4Header! - {:?}",
                error
            );
            return None;
        }
    };

    header.identification = identification;
    let builder = PacketBuilder::ip(IpHeaders::Ipv4(header, Default::default()));
    return build_ip_packet_with_udp_payload(builder, source_port, destination_port, udp_payload);
}

fn build_ipv6_packet_with_udp_payload(
    source_address: &[u8; 16],
    source_port: u16,
    destination_address: &[u8; 16],
    destination_port: u16,
    traffic_class: u8,
    flow_label: Ipv6FlowLabel,
    hop_limit: u8,
    udp_payload: &[u8],
) -> Option<Vec<u8>> {
    let header = Ipv6Header {
        traffic_class,
        flow_label,
        payload_length: udp_payload.len() as u16,
        next_header: IpNumber::UDP,
        hop_limit,
        source: *source_address,
        destination: *destination_address,
    };
    let builder = PacketBuilder::ip(IpHeaders::Ipv6(header, Default::default()));
    return build_ip_packet_with_udp_payload(builder, source_port, destination_port, udp_payload);
}

fn build_ip_packet_with_udp_payload(
    builder: PacketBuilderStep<IpHeaders>,
    source_port: u16,
    destination_port: u16,
    udp_payload: &[u8],
) -> Option<Vec<u8>> {
    let udp_builder = builder.udp(source_port, destination_port);
    let mut result = Vec::<u8>::with_capacity(udp_builder.size(udp_payload.len()));
    if let Err(error) = udp_builder.write(&mut result, &udp_payload) {
        error!("build_packet: Failed to build packet! - {:?}", error);
        return None;
    }
    return Some(result);
}

/// Takes the header information from the request packet and builds a new packet using it and the response payload
pub fn build_response_ip_packet(request_ip_packet: &[u8], response_udp_payload: &[u8]) -> Option<Vec<u8>> {
    let generic_request_packet = match GenericIpPacket::new(request_ip_packet) {
        Some(value) => value,
        None => return None,
    };

    let request_payload = match generic_request_packet.get_udp_packet() {
        Some(value) => value,
        None => return None,
    };

    match &generic_request_packet.header {
        IpHeaders::Ipv4(ipv4_header, _) => build_ipv4_packet_with_udp_payload(
            &ipv4_header.destination,
            request_payload.destination_port(),
            &ipv4_header.source,
            request_payload.source_port(),
            ipv4_header.time_to_live,
            ipv4_header.identification,
            &response_udp_payload,
        ),
        IpHeaders::Ipv6(ipv6_header, _) => build_ipv6_packet_with_udp_payload(
            &ipv6_header.destination,
            request_payload.destination_port(),
            &ipv6_header.source,
            request_payload.source_port(),
            ipv6_header.traffic_class,
            ipv6_header.flow_label,
            ipv6_header.hop_limit,
            &response_udp_payload,
        ),
    }
}
