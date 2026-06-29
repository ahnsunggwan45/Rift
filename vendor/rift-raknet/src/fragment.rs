use crate::arq::{FrameSetPacket, Reliability};
use crate::error::*;
use std::collections::HashMap;

struct Fragment {
    pub flags: u8,
    pub compound_size: u32,
    pub ordered_frame_index: u32,
    pub frames: HashMap<u32, FrameSetPacket>,
}

impl Fragment {
    pub fn new(flags: u8, compound_size: u32, ordered_frame_index: u32) -> Self {
        Self {
            flags,
            compound_size,
            ordered_frame_index,
            frames: HashMap::new(),
        }
    }

    pub fn full(&self) -> bool {
        self.frames.len() == self.compound_size as usize
    }

    pub fn insert(&mut self, frame: FrameSetPacket) {
        if self.full() {
            return;
        }

        if self.frames.contains_key(&frame.fragment_index) {
            return;
        }

        self.frames.insert(frame.fragment_index, frame);
    }

    pub fn merge(&mut self) -> Result<FrameSetPacket> {
        let mut buf = vec![];

        let mut keys: Vec<u32> = self.frames.keys().cloned().collect();

        keys.sort_unstable();

        let sequence_number = self.frames[keys.last().unwrap()].sequence_number;

        for i in keys {
            buf.extend_from_slice(&self.frames[&i].data);
        }

        let mut ret = FrameSetPacket::new(Reliability::from((self.flags & 224) >> 5)?, buf);

        ret.ordered_frame_index = self.ordered_frame_index;
        ret.sequence_number = sequence_number;
        Ok(ret)
    }
}

pub struct FragmentQ {
    fragments: HashMap<u16, Fragment>,
}

// Rift hardening: prevent unbounded accumulation of incomplete fragments (memory-exhaustion DoS).
// Normal traffic never comes close to these limits — excess fragments are silently dropped
// (reliable packets will be retransmitted).
//
// compound_size cap: at MTU 1200, 16384 fragments ≈ 19 MB — far larger than any legitimate
// Bedrock packet, including full chunk batches.
const MAX_COMPOUND_SIZE: u32 = 16384;
// Concurrent incomplete-compound cap: normal sessions have 1–2 at most.
// Blocks malicious accumulation of many distinct compound_ids.
const MAX_CONCURRENT_COMPOUNDS: usize = 256;

impl FragmentQ {
    pub fn new() -> Self {
        Self {
            fragments: HashMap::new(),
        }
    }

    pub fn insert(&mut self, frame: FrameSetPacket) {
        // Reject abnormal compound_size (zero or oversized) — blocks accumulation attacks
        // that claim an inflated fragment count.
        if frame.compound_size == 0 || frame.compound_size > MAX_COMPOUND_SIZE {
            return;
        }
        if self.fragments.contains_key(&frame.compound_id) {
            self.fragments
                .get_mut(&frame.compound_id)
                .unwrap()
                .insert(frame);
        } else {
            // New compound: reject if we already have too many incomplete compounds —
            // prevents DoS via accumulation of many distinct incomplete compounds.
            if self.fragments.len() >= MAX_CONCURRENT_COMPOUNDS {
                return;
            }
            let mut v = Fragment::new(frame.flags, frame.compound_size, frame.ordered_frame_index);
            let k = frame.compound_id;
            v.insert(frame);
            self.fragments.insert(k, v);
        }
    }

    pub fn flush(&mut self) -> Result<Vec<FrameSetPacket>> {
        let mut ret = vec![];

        let keys: Vec<u16> = self.fragments.keys().cloned().collect();

        for i in keys {
            let a = self.fragments.get_mut(&i).unwrap();
            if a.full() {
                ret.push(a.merge()?);
                self.fragments.remove(&i);
            }
        }

        Ok(ret)
    }

    pub fn size(&self) -> usize {
        self.fragments.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arq::{FrameSetPacket, Reliability};

    fn make(compound_id: u16, compound_size: u32, index: u32) -> FrameSetPacket {
        let mut f = FrameSetPacket::new(Reliability::ReliableOrdered, vec![1u8, 2, 3]);
        f.compound_id = compound_id;
        f.compound_size = compound_size;
        f.fragment_index = index;
        f
    }

    #[test]
    fn rejects_abnormal_compound_size() {
        let mut q = FragmentQ::new();
        q.insert(make(1, MAX_COMPOUND_SIZE + 1, 0));
        q.insert(make(2, 0, 0));
        assert_eq!(q.size(), 0, "oversized/zero compound_size must be rejected");
    }

    #[test]
    fn caps_concurrent_incomplete_compounds() {
        let mut q = FragmentQ::new();
        // Insert only one fragment per compound to keep each one incomplete — stress-test accumulation.
        for id in 0..(MAX_CONCURRENT_COMPOUNDS as u16 + 50) {
            q.insert(make(id, 4, 0));
        }
        assert_eq!(
            q.size(),
            MAX_CONCURRENT_COMPOUNDS,
            "concurrent incomplete compounds must be capped at the limit"
        );
    }

    #[test]
    fn normal_reassembly_still_works() {
        let mut q = FragmentQ::new();
        q.insert(make(7, 2, 0));
        q.insert(make(7, 2, 1));
        let flushed = q.flush().unwrap();
        assert_eq!(flushed.len(), 1, "a complete 2-fragment compound must be reassembled");
        assert_eq!(q.size(), 0, "a completed compound must be removed from the queue");
    }
}
