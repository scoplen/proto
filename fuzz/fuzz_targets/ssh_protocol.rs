// SPDX-License-Identifier: Apache-2.0
#![no_main]

use libfuzzer_sys::fuzz_target;
use scoplen_ssh::{
    ChannelClose, ChannelData, ChannelEof, ChannelExtendedData, ChannelFailure, ChannelOpen,
    ChannelOpenConfirmation, ChannelOpenFailure, ChannelRequest, ChannelSuccess,
    ChannelWindowAdjust, GlobalRequest, GlobalRequestFailure, GlobalRequestSuccess,
    KeyboardInteractiveInfoRequest, KeyboardInteractiveResponse, KeyExchangeFamily,
    SftpLimits, SftpPacket, SftpStatvfs, SocksHandshake, StrictKexPacket, StrictKeyExchange,
};

fuzz_target!(|bytes: &[u8]| {
    let _ = ChannelOpen::decode(bytes);
    let _ = ChannelOpenConfirmation::decode(bytes);
    let _ = ChannelOpenFailure::decode(bytes);
    let _ = ChannelData::decode(bytes);
    let _ = ChannelExtendedData::decode(bytes);
    let _ = ChannelWindowAdjust::decode(bytes);
    let _ = ChannelEof::decode(bytes);
    let _ = ChannelClose::decode(bytes);
    let _ = ChannelSuccess::decode(bytes);
    let _ = ChannelFailure::decode(bytes);
    let _ = ChannelRequest::decode(bytes);
    let _ = GlobalRequest::decode(bytes);
    let _ = GlobalRequestSuccess::decode(bytes);
    let _ = GlobalRequestFailure::decode(bytes);
    let _ = KeyboardInteractiveInfoRequest::decode(bytes);
    let _ = KeyboardInteractiveResponse::decode(bytes);
    let _ = SftpPacket::decode(bytes);
    let _ = SftpLimits::decode(bytes);
    let _ = SftpStatvfs::decode(bytes);

    let mut socks = SocksHandshake::new();
    let _ = socks.feed(bytes);
    let _ = socks.finish();

    let mut strict = StrictKeyExchange::new(true, KeyExchangeFamily::Ecdh);
    for byte in bytes.iter().take(128) {
        let packet = match byte % 14 {
            0 => StrictKexPacket::KexInit,
            1 => StrictKexPacket::NewKeys,
            2 => StrictKexPacket::KexDhInit,
            3 => StrictKexPacket::KexDhReply,
            4 => StrictKexPacket::KexDhGexRequestOld,
            5 => StrictKexPacket::KexDhGexRequest,
            6 => StrictKexPacket::KexDhGexGroup,
            7 => StrictKexPacket::KexDhGexInit,
            8 => StrictKexPacket::KexDhGexReply,
            9 => StrictKexPacket::KexEcdhInit,
            10 => StrictKexPacket::KexEcdhReply,
            11 => StrictKexPacket::KexHybridInit,
            12 => StrictKexPacket::KexHybridReply,
            _ => StrictKexPacket::ExtInfo,
        };
        let _ = strict.on_receive(packet);
    }
});
