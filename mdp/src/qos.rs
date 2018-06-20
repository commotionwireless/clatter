use std::{
    cell::RefCell,
    cmp::Ordering,
    collections::{BinaryHeap, binary_heap::Iter},
    ops::{Index, IndexMut},
    time::{Duration, Instant},
    vec::Vec
};

use addr::Addr;
use error::{Error, Result};
use message::Message;
use util::BitMask;

const MAX_LENGTH: usize = 100;
const MAX_QUEUES: usize = 5;

#[derive(Debug)]
pub(crate) enum QueuedState {
    Unsent(i8),
    Sent { seq: i8, dst: RefCell<Vec<Addr>> },
}

#[derive(Debug)]
pub(crate) struct QueuedInfo {
    send_at: Instant,
    enqueued_at: Instant,
    state: QueuedState,
}

impl QueuedInfo {
    pub fn state(&self) -> &QueuedState {
        &self.state
    }
}

struct QueuedMessage {
    inner: RefCell<Option<Message>>,
    info: QueuedInfo,
}

impl QueuedMessage {
    fn new(message: Message, info: QueuedInfo) -> QueuedMessage {
        QueuedMessage {
            inner: RefCell::new(Some(message)),
            info: info,
        }
    }

    fn unsent(message: Message, iface: i8, send_in: u64) -> QueuedMessage {
        let now = Instant::now();
        QueuedMessage::new(
            message,
            QueuedInfo {
                send_at: now + Duration::from_millis(send_in),
                enqueued_at: now,
                state: QueuedState::Unsent(iface),
            },
        )
    }

    fn sent(message: Message, send_in: Duration, seq: i8, dst: Vec<Addr>) -> QueuedMessage {
        let now = Instant::now();
        QueuedMessage::new(
            message,
            QueuedInfo {
                send_at: now + send_in,
                enqueued_at: now,
                state: QueuedState::Sent {
                    seq: seq,
                    dst: RefCell::new(dst),
                },
            },
        )
    }
}

impl PartialEq for QueuedMessage {
    fn eq(&self, other: &QueuedMessage) -> bool {
        self.info.send_at.eq(&other.info.send_at)
    }
}

impl Eq for QueuedMessage {}

impl PartialOrd for QueuedMessage {
    fn partial_cmp(&self, other: &QueuedMessage) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for QueuedMessage {
    fn cmp(&self, other: &QueuedMessage) -> Ordering {
        other.info.send_at.cmp(&self.info.send_at)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Class {
    Voice = 0,
    Management = 1,
    Video = 2,
    Ordinary = 3,
    Opportunistic = 4,
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

pub(crate) struct Bucket {
    messages: BinaryHeap<QueuedMessage>,
    max_length: usize,
    max_latency: Duration,
}

impl Bucket {
    fn new() -> Bucket {
        Bucket {
            messages: BinaryHeap::new(),
            max_length: MAX_LENGTH,
            max_latency: Duration::from_millis(0),
        }
    }

    fn len(&self) -> usize {
        self.messages.len()
    }

    fn iter(&self) -> Iter<QueuedMessage> {
        self.messages.iter()
    }

    fn try_push(&mut self, p: QueuedMessage) -> Result<()> {
        if self.len() >= self.max_length {
            Err(Error::QueueCongestion)
        } else {
            Ok(self.messages.push(p))
        }
    }
}

pub(crate) struct Queue {
    buckets: Vec<Bucket>,
    index: u8,
}

impl Queue {
    pub fn new() -> Queue {
        let mut queue = Queue {
            buckets: (0..MAX_QUEUES).map(|_| Bucket::new()).collect(),
            index: 0,
        };
        queue[Class::Voice].max_length = 20;
        queue[Class::Voice].max_latency = Duration::from_millis(200);
        queue[Class::Video].max_latency = Duration::from_millis(200);
        queue
    }

    pub fn schedule(&mut self, p: Message, iface: i8, ms: u64) -> Result<()> {
        if let Some(b) = self.buckets.get_mut(p.qos as usize) {
            b.try_push(QueuedMessage::unsent(p, iface, ms))
        } else {
            Err(Error::QueueCongestion)
        }
    }

    pub fn reschedule(&mut self, p: Message, ms: Duration, seq: i8, dst: Vec<Addr>) -> Result<()> {
        debug!("Rescheduled message {} for resending in {:?} ms.", seq, ms);
        if let Some(b) = self.buckets.get_mut(p.qos as usize) {
            b.try_push(QueuedMessage::sent(p, ms, seq, dst))
        } else {
            Err(Error::QueueCongestion)
        }
    }

    pub fn requeue(&mut self, p: Message, q: QueuedInfo) -> Result<()> {
        if let Some(b) = self.buckets.get_mut(p.qos as usize) {
            b.try_push(QueuedMessage::new(p, q))
        } else {
            Err(Error::QueueCongestion)
        }
    }

    pub fn len(&self) -> usize {
        self.buckets.iter().fold(0, |len, q| len + q.len())
    }

    fn try_next(&mut self, tries: u8) -> Option<(Message, QueuedInfo)> {
        let len = self.buckets.len();
        if tries as usize >= len {
            return None;
        }
        if self.index as usize >= len {
            self.index = 0;
        }
        let max_latency = self.buckets[self.index as usize].max_latency;
        let zero = Duration::new(0, 0);
        match self.buckets[self.index as usize].messages.pop() {
            Some(QueuedMessage { inner: c, info: i }) => {
                if let Some(p) = c.into_inner() {
                    let now = Instant::now();
                    if max_latency > zero && i.enqueued_at + max_latency < now {
                        debug!("Dropping outgoing message due to timeout.");
                        self.index += 1;
                        self.try_next(tries + 1)
                    } else if i.send_at > now {
                        debug!(
                            "Requeueing outgoing message due at {:?} (it is now {:?}).",
                            i.send_at, now
                        );
                        let _ = self.requeue(p, i)
                            .map_err(|e| error!("Error requeueing message for sending: {:?}", e));
                        self.index += 1;
                        self.try_next(tries + 1)
                    } else {
                        debug!(
                            "Popping outgoing message from queue for delivery with state {:?}.",
                            i.state
                        );
                        Some((p, i))
                    }
                } else {
                    self.index += 1;
                    self.try_next(tries + 1)
                }
            }
            _ => {
                self.index += 1;
                self.try_next(tries + 1)
            }
        }
    }

    pub fn ack(
        &mut self,
        neighbor: &Addr,
        ack_seq: i8,
        ack_mask: u32,
    ) -> Option<(Duration, Duration)> {
        debug!(
            "Received ACK for frame with sequence {} from neighbor {:?}.",
            ack_seq, neighbor
        );
        let zero = Duration::new(0, 0);
        let mut min_rtt = Duration::new(0, 0);
        let mut max_rtt = Duration::new(0, 0);
        let mut acked = false;
        for ref mut b in &mut self.buckets {
            for p in b.iter() {
                if b.max_latency > zero && p.info.enqueued_at + b.max_latency < Instant::now() {
                    debug!("Timing out frame with sequence {}.", ack_seq);
                    *p.inner.borrow_mut() = None;
                }
                match p.info.state {
                    QueuedState::Sent { seq, ref dst } => {
                        let mut dst = dst.borrow_mut();
                        let len = dst.len();
                        if len > 0 {
                            if let Ok(index) = dst.binary_search(neighbor) {
                                debug!("Ack'ing sent frame with sequence {}.", ack_seq);
                                let delta = (ack_seq - seq).abs();
                                if delta == 0 || ack_mask.nth_bit_is_set(delta as u32) {
                                    acked = true;
                                    dst.swap_remove(index);
                                    if len == 1 {
                                        *p.inner.borrow_mut() = None;
                                    }
                                    let rtt = p.info.enqueued_at.elapsed();
                                    if rtt > max_rtt {
                                        max_rtt = rtt;
                                    }
                                    if rtt < min_rtt || min_rtt == zero {
                                        min_rtt = rtt;
                                    }
                                }
                            }
                        }
                    }
                    _ => continue,
                }
            }
        }
        if acked {
            debug!("ACK'd frame!");
            Some((min_rtt, max_rtt))
        } else {
            None
        }
    }
}

impl Iterator for Queue {
    type Item = (Message, QueuedInfo);

    fn next(&mut self) -> Option<(Message, QueuedInfo)> {
        self.try_next(0)
    }
}

#[cfg(test)]
mod tests {
    extern crate env_logger;
    use super::*;
    use bytes::BytesMut;
    use addr::*;
    use message::*;
    use std::thread::sleep;

    #[test]
    fn queue_order() {
        let _ = env_logger::try_init();
        let mut queue = Queue::new();
        let s1 = LocalAddr::new();
        let s2 = LocalAddr::new();
        let s3 = LocalAddr::new();
        let p1 = Message::new(
            (&s1, 1),
            (&s3, 1),
            &s2,
            10,
            QOS_DEFAULT,
            0,
            false,
            &mut BytesMut::from(&b"Message1"[..]),
        );
        let p2 = Message::new(
            (&s1, 1),
            (&s2, 1),
            &s2,
            10,
            Class::Management,
            0,
            false,
            &mut BytesMut::from(&b"Message2"[..]),
        );
        let p3 = Message::new(
            (&s1, 1),
            (&s2, 1),
            &s2,
            10,
            QOS_DEFAULT,
            0,
            false,
            &mut BytesMut::from(&b"Message3"[..]),
        );
        let p1c = p1.clone();
        let p2c = p2.clone();
        let p3c = p3.clone();
        queue.schedule(p1, 0, 3).unwrap();
        queue.schedule(p2, 0, 2).unwrap();
        queue.schedule(p3, 0, 1).unwrap();
        sleep(Duration::from_millis(4));
        let (p2d, _) = queue.next().unwrap();
        let (p3d, _) = queue.next().unwrap();
        let (p1d, _) = queue.next().unwrap();
        println!("p1d: {:?}", p1d);
        println!("p2d: {:?}", p2d);
        println!("p3d: {:?}", p3d);
        println!("first: {:?}", p2d);
        println!("second: {:?}", p3d);
        println!("third: {:?}", p1d);
        assert!(p1d.equiv(&p1c) && p2c.equiv(&p2d) && p3c.equiv(&p3d))
    }

    #[test]
    fn queue_ack() {
        let _ = env_logger::try_init();
        let mut queue = Queue::new();
        let s1 = LocalAddr::new();
        let s2 = LocalAddr::new();
        let s3 = LocalAddr::new();
        let p1 = Message::new(
            (&s1, 1),
            (&s3, 1),
            &s2,
            10,
            QOS_DEFAULT,
            0,
            false,
            &mut BytesMut::from(&b"Message1"[..]),
        );
        let p2 = Message::new(
            (&s1, 1),
            (&s2, 1),
            &s2,
            10,
            Class::Management,
            12,
            false,
            &mut BytesMut::from(&b"Message2"[..]),
        );
        let p3 = Message::new(
            (&s1, 1),
            (&s2, 1),
            &s2,
            10,
            QOS_DEFAULT,
            42,
            false,
            &mut BytesMut::from(&b"Message3"[..]),
        );
        let p1c = p1.clone();
        let dst = Addr::from(&s2);
        queue
            .reschedule(p1, Duration::from_millis(1), 0, vec![dst])
            .unwrap();
        queue
            .reschedule(p2, Duration::from_millis(1), 12, vec![dst])
            .unwrap();
        queue
            .reschedule(p3, Duration::from_millis(1), 42, vec![dst])
            .unwrap();
        queue.ack(&dst, 12, 0);
        queue.ack(&dst, 13, 268435456);
        sleep(Duration::from_millis(2));
        let (p1d, _) = queue.next().unwrap();
        let p2d = queue.next();
        info!("p1d: {:?}", p1d);
        assert!(p1d.equiv(&p1c) && p2d.is_none())
    }

    #[test]
    fn queue_timeout() {
        let _ = env_logger::try_init();
        let mut queue = Queue::new();
        let s1 = LocalAddr::new();
        let p1 = Message::new(
            (&s1, 1),
            (&s1, 1),
            &s1,
            10,
            Class::Voice,
            0,
            false,
            &mut BytesMut::from(&b"Message1"[..]),
        );
        queue.schedule(p1, 0, 0).unwrap();
        sleep(Duration::from_millis(201));
        let p1d = queue.next();
        assert!(p1d.is_none())
    }
}
