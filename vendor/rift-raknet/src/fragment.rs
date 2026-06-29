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

// Rift 하드닝: 미완성 조각의 무한 누적(메모리 고갈 DoS) 방지.
// 정상 트래픽은 이 한도 근처에도 못 간다 — 한도 초과 조각은 조용히 드롭(신뢰 패킷이면 재전송됨).
//
// compound_size 상한: MTU 1200 기준 16384 조각 ≈ 19MB. 어떤 정상 Bedrock 패킷(청크 배치 포함)보다 훨씬 크다.
const MAX_COMPOUND_SIZE: u32 = 16384;
// 동시 미완성 compound 수 상한: 정상은 1~2개. 악의적 다수 compound_id 누적을 차단.
const MAX_CONCURRENT_COMPOUNDS: usize = 256;

impl FragmentQ {
    pub fn new() -> Self {
        Self {
            fragments: HashMap::new(),
        }
    }

    pub fn insert(&mut self, frame: FrameSetPacket) {
        // 비정상 compound_size(0 또는 과대) 거부 — 거대 조각수 주장으로 누적시키는 공격 차단.
        if frame.compound_size == 0 || frame.compound_size > MAX_COMPOUND_SIZE {
            return;
        }
        if self.fragments.contains_key(&frame.compound_id) {
            self.fragments
                .get_mut(&frame.compound_id)
                .unwrap()
                .insert(frame);
        } else {
            // 새 compound 인데 동시 미완성이 한도면 거부 — 다수 미완성 compound 누적 DoS 차단.
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
        assert_eq!(q.size(), 0, "과대/0 compound_size 는 거부되어야 함");
    }

    #[test]
    fn caps_concurrent_incomplete_compounds() {
        let mut q = FragmentQ::new();
        // 각 compound 에 조각 1개만 넣어 미완성으로 남긴다 → 누적 시도.
        for id in 0..(MAX_CONCURRENT_COMPOUNDS as u16 + 50) {
            q.insert(make(id, 4, 0));
        }
        assert_eq!(
            q.size(),
            MAX_CONCURRENT_COMPOUNDS,
            "동시 미완성 compound 는 상한에서 멈춰야 함"
        );
    }

    #[test]
    fn normal_reassembly_still_works() {
        let mut q = FragmentQ::new();
        q.insert(make(7, 2, 0));
        q.insert(make(7, 2, 1));
        let flushed = q.flush().unwrap();
        assert_eq!(flushed.len(), 1, "정상 2조각은 재조립되어야 함");
        assert_eq!(q.size(), 0, "완성된 compound 는 제거되어야 함");
    }
}
