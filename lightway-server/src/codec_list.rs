use lightway_core::WeakPacketEncoderType;
use std::{collections::HashMap, net::Ipv4Addr};

// Maps client's internal IP (assigned by IPManager) to its connection's packet encoder
pub type InternalIPToEncoderMap = HashMap<Ipv4Addr, WeakPacketEncoderType>;
