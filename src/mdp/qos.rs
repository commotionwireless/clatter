use std::vec::Vec;
use std::collections::BinaryHeap;
use std::collections::binary_heap::Iter;
use std::ops::{Index, IndexMut};
use std::cmp::Ordering;
use std::cell::RefCell;
use std::time::{Duration, Instant};
use mdp::error::{Error, Result};
use mdp::packet::Packet;
use mdp::addr::Addr;
use mdp::util::BitMask;

const MAX_LENGTH: usize = 100;
const MAX_QUEUES: usize = 5;
//const SMALL_PACKET: usize = 400;

enum QueuedState {
    Unsent,
    Sent {
        seq: i8,
        dst: RefCell<Vec<Addr>>
    }
}

pub struct QueuedInfo {
    send_at: Instant,
    enqueued_at: Instant,
    state: QueuedState
}

struct QueuedPacket {
    inner: RefCell<Option<Packet>>,
    info: QueuedInfo
}

impl QueuedPacket {
    fn new(packet: Packet, info: QueuedInfo) -> QueuedPacket {
        QueuedPacket {
            inner: RefCell::new(Some(packet)),
            info: info
        }
    }

    fn unsent(packet: Packet, send_in: u64) -> QueuedPacket {
        let now = Instant::now();
        QueuedPacket::new(packet,
            QueuedInfo {
                send_at: now + Duration::from_millis(send_in),
                enqueued_at: now,
                state: QueuedState::Unsent
            }
        )
    }

    fn sent(packet: Packet, send_in: u64, seq: i8, dst: Vec<Addr>) -> QueuedPacket {
        let now = Instant::now();
        QueuedPacket::new(packet,
            QueuedInfo {
                send_at: now + Duration::from_millis(send_in),
                enqueued_at: now,
                state: QueuedState::Sent { seq: seq, dst: RefCell::new(dst) }
            }
        )
    }

//    fn len(&self, frame_src: Addr) -> usize {
//        if let Cell { Some(p) } = self.inner {
//            p.len(frame_src)
//        } else {
//            0
//        }
//    }
}

impl PartialEq for QueuedPacket {
    fn eq(&self, other: &QueuedPacket) -> bool {
        self.info.send_at.eq(&other.info.send_at)
    }
}

impl Eq for QueuedPacket {}

impl PartialOrd for QueuedPacket {
    fn partial_cmp(&self, other: &QueuedPacket) -> Option<Ordering> {
        self.info.send_at.partial_cmp(&other.info.send_at)
    }
}

impl Ord for QueuedPacket {
    fn cmp(&self, other: &QueuedPacket) -> Ordering {
        self.info.send_at.cmp(&other.info.send_at)
    }
}


#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Class {
    Voice = 0,
    Management = 1,
    Video = 2,
    Ordinary = 3,
    Opportunistic = 4
}

impl Index<Class> for Queue {
    type Output = Bucket;

    fn index(&self, index: Class) -> &Bucket {
        &self.buckets[index as usize]
    }
}

impl IndexMut<Class> for Queue {
    fn index_mut(&mut self, index: Class) -> &mut Bucket {
        &mut self.buckets[index as usize]
    }
}

pub struct Bucket {
    packets: BinaryHeap<QueuedPacket>,
    max_length: usize,
    max_latency: Duration,
    //small_packet_grace: time::Duration
}

impl Bucket {
    fn len(&self) -> usize {
        self.packets.len()
    }

//    fn plen(&self, frame_src: Addr) -> usize {
//        self.packets.iter().fold(0, |len, ref p| len + p.len(frame_src))
//    }

    fn iter(&self) -> Iter<QueuedPacket> {
        self.packets.iter()
    }

    fn try_push(&mut self, p: QueuedPacket) -> Result<()> {
        if self.len() >= self.max_length {
            Err(Error::QueueCongestion)
        } else {
            Ok(self.packets.push(p))
        }
    }
}

impl Default for Bucket {
    fn default() -> Bucket {
        Bucket {
            packets: BinaryHeap::new(),
            max_length: MAX_LENGTH,
            max_latency: Duration::from_millis(0),
            //small_packet_grace: Duration::from_millis(5)
        }
    }
}

pub struct Queue {
    buckets: Vec<Bucket>,
    index: u8,
}

impl Queue {
    pub fn new() -> Queue {
        let mut b = Vec::new();
        for i in 0..(MAX_QUEUES - 1) {
            b[i] = Default::default();
        }
        let mut queue = Queue {
            buckets: b,
            index: 0
        };
        queue[Class::Voice].max_length = 20;
        queue[Class::Voice].max_latency = Duration::from_millis(200);
        queue[Class::Video].max_latency = Duration::from_millis(200);
        //q[Class::Opportunistic].small_packet_grace = Duration::from_millis(100);
        queue
    }

    pub fn schedule(&mut self, p: Packet, ms: u64) -> Result<()> {
        if let Some(b) = self.buckets.get_mut(p.qos as usize) {
            b.try_push(QueuedPacket::unsent(p, ms))
        } else {
            Err(Error::QueueCongestion)
        }
    }

    pub fn reschedule(&mut self, p: Packet, ms: u64, seq: i8, dst: Vec<Addr>) -> Result<()> {
        if let Some(b) = self.buckets.get_mut(p.qos as usize) {
            b.try_push(QueuedPacket::sent(p, ms, seq, dst))
        } else {
            Err(Error::QueueCongestion)
        }
    }

    pub fn requeue(&mut self, p: Packet, q: QueuedInfo) -> Result<()> {
        if let Some(b) = self.buckets.get_mut(p.qos as usize) {
            b.try_push(QueuedPacket::new(p, q))
        } else {
            Err(Error::QueueCongestion)
        }
    }

    pub fn len(&self) -> usize {
        self.buckets.iter().fold(0, |len, ref q| len + q.len())
    }

//    pub fn plen(&self, frame_src: Addr) -> usize {
//        self.buckets.iter().fold(0, |all, ref q| all + q.plen(frame_src))
//    }

//    fn try_peek(&mut self, tries: u8) -> Option<&Packet> {
//        if tries as usize >= self.buckets.len() {
//            return None;
//        }
//        if self.index as usize >= MAX_QUEUES {
//            self.index = 0;
//        }
//        if let Some(q) = self.buckets[self.index as usize].packets.peek() {
//            if q.info.send_at <= Instant::now() {
//                if let Some(p) = q.inner {
//                    Some(&p)
//                } else {
//                    None
//                }
//            } else {
//                None
//            }
//        } else {
//            self.index += 1;
//            self.try_peek(tries + 1)
//        }
//    }
//
//    pub fn peek(&mut self) -> Option<&Packet> {
//        self.try_peek(0)
//    }

    fn try_next(&mut self, tries: u8) -> Option<(Packet, QueuedInfo)> {
        if tries as usize >= self.buckets.len() {
            return None;
        }
        if self.index as usize >= MAX_QUEUES {
            self.index = 0;
        }
        match self.buckets[self.index as usize].packets.pop() {
                Some(QueuedPacket { inner: c, info: i }) => {
                    if let Some(p) = c.into_inner() {
                        Some((p, i))
                    } else {
                        self.index += 1;
                        self.try_next(tries + 1)
                    }
                },
                _ => {
                    self.index += 1;
                    self.try_next(tries + 1)
                }
        }
    }


    pub fn ack(&mut self, neighbor: Addr, ack_seq: i8, ack_mask: u32) -> Option<(Duration, Duration)> {
        let zero = Duration::new(0, 0);
        let mut min_rtt = Duration::new(0, 0);
        let mut max_rtt = Duration::new(0, 0);
        let mut acked = false;
        for b in self.buckets.iter_mut() {
            for p in b.iter() {
                if b.max_latency > zero && p.info.enqueued_at + b.max_latency < Instant::now() {
                    *p.inner.borrow_mut() = None;
                }
                match p.info.state {
                    QueuedState::Sent { seq, ref dst } => {
                        let mut dst = dst.borrow_mut();
                        if !dst.is_empty() {
                            if let Ok(index) = dst.binary_search(&neighbor) {
                                let delta = ack_seq - seq;
                                if delta == 0 || ack_mask.nth_bit_is_set(delta) {
                                    acked = true;
                                    dst.swap_remove(index);
                                    let rtt = p.info.enqueued_at.elapsed();
                                    if rtt > max_rtt {
                                        max_rtt = rtt;
                                    }
                                    if rtt < min_rtt || min_rtt == zero {
                                        min_rtt = rtt;
                                    }
                                }
                            }
                        } else {
                            *p.inner.borrow_mut() = None;
                            continue
                        }
                    },
                    _ => continue
                }
            }
        }
        if acked {
            Some((min_rtt, max_rtt))
        } else {
            None
        }
    }
}

impl Iterator for Queue {
    type Item = (Packet, QueuedInfo);

    fn next(&mut self) -> Option<(Packet, QueuedInfo)> {
        self.try_next(0)
    }
}
