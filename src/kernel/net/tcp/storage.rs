//! TCP storage structures: RingBuffer and Assembler
//!
//! This module provides zero-copy storage primitives for TCP:
//! - RingBuffer: Circular buffer with borrowed lifetime
//! - Assembler: Out-of-order packet reassembly

use core::cmp;
use core::fmt;

// ========== RingBuffer ==========

/// A circular buffer with borrowed lifetime, matching smoltcp's design.
///
/// This buffer borrows a mutable slice and provides efficient circular
/// queue operations without allocation. The lifetime parameter ensures
/// the buffer cannot outlive its underlying storage.
pub struct RingBuffer<'a, T: 'a> {
    storage: &'a mut [T],
    read_at: usize,
    length: usize,
}

impl<'a, T> RingBuffer<'a, T> {
    /// Create a new ring buffer from a mutable slice.
    pub fn new(storage: &'a mut [T]) -> Self {
        RingBuffer {
            storage,
            read_at: 0,
            length: 0,
        }
    }

    /// Return true if the buffer is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Return true if the buffer is full.
    #[inline]
    pub fn is_full(&self) -> bool {
        self.length == self.storage.len()
    }

    /// Return the number of elements currently in the buffer.
    #[inline]
    pub fn len(&self) -> usize {
        self.length
    }

    /// Return the total capacity of the buffer.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.storage.len()
    }

    /// Return the number of elements that can be written.
    #[inline]
    pub fn window(&self) -> usize {
        self.storage.len() - self.length
    }

    /// Get write position.
    #[inline]
    fn write_at(&self) -> usize {
        let mut write_at = self.read_at + self.length;
        if write_at >= self.storage.len() {
            write_at -= self.storage.len();
        }
        write_at
    }

    /// Get contiguous readable slice starting at offset.
    pub fn get_allocated(&self, offset: usize, size: usize) -> Option<&[T]> {
        if offset + size > self.length {
            return None;
        }

        let start = self.read_at + offset;
        if start >= self.storage.len() {
            // Wrapped around
            let start = start - self.storage.len();
            let end = cmp::min(start + size, self.storage.len());
            Some(&self.storage[start..end])
        } else if start + size > self.storage.len() {
            // Would wrap - return only contiguous part
            Some(&self.storage[start..])
        } else {
            Some(&self.storage[start..start + size])
        }
    }
}

impl<'a, T: Copy> RingBuffer<'a, T> {
    /// Enqueue a slice of elements, returning the number written.
    pub fn enqueue_slice(&mut self, data: &[T]) -> usize {
        let available = self.window();
        let to_write = cmp::min(data.len(), available);

        if to_write == 0 {
            return 0;
        }

        let write_at = self.write_at();
        let contiguous = cmp::min(to_write, self.storage.len() - write_at);

        // Write contiguous part
        self.storage[write_at..write_at + contiguous].copy_from_slice(&data[..contiguous]);

        // Write wrapped part if any
        if contiguous < to_write {
            let remainder = to_write - contiguous;
            self.storage[..remainder].copy_from_slice(&data[contiguous..to_write]);
        }

        self.length += to_write;
        to_write
    }

    /// Dequeue elements into a slice, returning the number read.
    pub fn dequeue_slice(&mut self, data: &mut [T]) -> usize {
        let to_read = cmp::min(data.len(), self.length);

        if to_read == 0 {
            return 0;
        }

        let contiguous = cmp::min(to_read, self.storage.len() - self.read_at);

        // Read contiguous part
        data[..contiguous].copy_from_slice(&self.storage[self.read_at..self.read_at + contiguous]);

        // Read wrapped part if any
        if contiguous < to_read {
            let remainder = to_read - contiguous;
            data[contiguous..to_read].copy_from_slice(&self.storage[..remainder]);
        }

        self.read_at += to_read;
        if self.read_at >= self.storage.len() {
            self.read_at -= self.storage.len();
        }
        self.length -= to_read;

        to_read
    }

    /// Peek at elements without removing them.
    pub fn peek_slice(&self, offset: usize, data: &mut [T]) -> usize {
        if offset >= self.length {
            return 0;
        }

        let available = self.length - offset;
        let to_read = cmp::min(data.len(), available);

        if to_read == 0 {
            return 0;
        }

        let start = self.read_at + offset;
        let start = if start >= self.storage.len() {
            start - self.storage.len()
        } else {
            start
        };

        let contiguous = cmp::min(to_read, self.storage.len() - start);

        // Read contiguous part
        data[..contiguous].copy_from_slice(&self.storage[start..start + contiguous]);

        // Read wrapped part if any
        if contiguous < to_read {
            let remainder = to_read - contiguous;
            data[contiguous..to_read].copy_from_slice(&self.storage[..remainder]);
        }

        to_read
    }

    /// Dequeue many elements, discarding them.
    pub fn dequeue_many(&mut self, count: usize) {
        let to_dequeue = cmp::min(count, self.length);
        self.read_at += to_dequeue;
        if self.read_at >= self.storage.len() {
            self.read_at -= self.storage.len();
        }
        self.length -= to_dequeue;
    }
}

impl<'a, T: Copy + fmt::Debug> fmt::Debug for RingBuffer<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RingBuffer")
            .field("capacity", &self.capacity())
            .field("length", &self.length)
            .field("read_at", &self.read_at)
            .finish()
    }
}

// ========== Assembler ==========

const ASSEMBLER_MAX_SEGMENT_COUNT: usize = 4;

/// Out-of-order TCP segment assembler.
///
/// Tracks up to ASSEMBLER_MAX_SEGMENT_COUNT non-contiguous segments
/// to handle out-of-order packet arrival. This is essential for TCP
/// reliability over lossy networks.
#[derive(Debug)]
pub struct Assembler {
    /// Contiguous blocks of received data.
    /// Each block has: (offset from base, size)
    contigs: [Contig; ASSEMBLER_MAX_SEGMENT_COUNT],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Contig {
    offset: usize,
    size: usize,
}

impl Contig {
    const EMPTY: Self = Contig { offset: 0, size: 0 };

    #[inline]
    fn is_empty(&self) -> bool {
        self.size == 0
    }

    #[inline]
    fn end(&self) -> usize {
        self.offset + self.size
    }
}

impl Assembler {
    /// Create a new assembler.
    pub fn new() -> Self {
        Assembler {
            contigs: [Contig::EMPTY; ASSEMBLER_MAX_SEGMENT_COUNT],
        }
    }

    /// Add a segment at the given offset and size.
    ///
    /// Returns true if the segment was added successfully.
    /// Returns false if the assembler is full.
    pub fn add(&mut self, offset: usize, size: usize) -> bool {
        if size == 0 {
            return true;
        }

        let new_end = offset + size;

        // Try to coalesce with existing segments
        let mut i = 0;
        while i < ASSEMBLER_MAX_SEGMENT_COUNT {
            if self.contigs[i].is_empty() {
                i += 1;
                continue;
            }

            let contig_end = self.contigs[i].end();

            // Check for overlap or adjacency
            if offset <= contig_end && new_end >= self.contigs[i].offset {
                // Merge segments
                let merged_start = cmp::min(offset, self.contigs[i].offset);
                let merged_end = cmp::max(new_end, contig_end);
                self.contigs[i].offset = merged_start;
                self.contigs[i].size = merged_end - merged_start;

                // Check if this merged segment can be combined with others
                self.coalesce_from(i);
                return true;
            }

            i += 1;
        }

        // No coalescence possible - find empty slot
        for contig in &mut self.contigs {
            if contig.is_empty() {
                *contig = Contig { offset, size };
                // Sort by offset to maintain order
                self.sort();
                return true;
            }
        }

        // No space - assembler is full
        false
    }

    /// Get the size of contiguous data available from offset 0.
    pub fn front(&self) -> usize {
        if self.contigs[0].is_empty() || self.contigs[0].offset != 0 {
            0
        } else {
            self.contigs[0].size
        }
    }

    /// Remove contiguous data from the front.
    pub fn remove_front(&mut self, size: usize) {
        if size == 0 {
            return;
        }

        if self.contigs[0].offset == 0 && self.contigs[0].size > 0 {
            if self.contigs[0].size <= size {
                // Remove entire first segment
                let removed_size = self.contigs[0].size;
                self.contigs[0] = Contig::EMPTY;

                // Shift all segments down by removed_size
                for contig in &mut self.contigs {
                    if !contig.is_empty() {
                        contig.offset = contig.offset.saturating_sub(removed_size);
                    }
                }

                // Recursively remove if more to remove
                if size > removed_size {
                    self.remove_front(size - removed_size);
                }
            } else {
                // Partial removal
                self.contigs[0].offset = 0;
                self.contigs[0].size -= size;

                // Shift all other segments
                for i in 1..ASSEMBLER_MAX_SEGMENT_COUNT {
                    if !self.contigs[i].is_empty() {
                        self.contigs[i].offset = self.contigs[i].offset.saturating_sub(size);
                    }
                }
            }

            self.sort();
        }
    }

    /// Check if assembler is empty.
    pub fn is_empty(&self) -> bool {
        self.contigs.iter().all(|c| c.is_empty())
    }

    /// Clear all segments.
    pub fn clear(&mut self) {
        for contig in &mut self.contigs {
            *contig = Contig::EMPTY;
        }
    }

    /// Coalesce contiguous segments starting from index i.
    fn coalesce_from(&mut self, start: usize) {
        let mut i = start;
        while i < ASSEMBLER_MAX_SEGMENT_COUNT - 1 {
            if self.contigs[i].is_empty() {
                break;
            }

            let mut j = i + 1;
            while j < ASSEMBLER_MAX_SEGMENT_COUNT {
                if self.contigs[j].is_empty() {
                    j += 1;
                    continue;
                }

                let i_end = self.contigs[i].end();
                let j_end = self.contigs[j].end();

                // Check if they overlap or are adjacent
                if self.contigs[i].offset <= j_end && i_end >= self.contigs[j].offset {
                    // Merge j into i
                    let merged_start = cmp::min(self.contigs[i].offset, self.contigs[j].offset);
                    let merged_end = cmp::max(i_end, j_end);
                    self.contigs[i].offset = merged_start;
                    self.contigs[i].size = merged_end - merged_start;
                    self.contigs[j] = Contig::EMPTY;
                }

                j += 1;
            }

            i += 1;
        }

        self.sort();
    }

    /// Sort segments by offset (bubble sort - fine for 4 elements).
    fn sort(&mut self) {
        for i in 0..ASSEMBLER_MAX_SEGMENT_COUNT {
            for j in i + 1..ASSEMBLER_MAX_SEGMENT_COUNT {
                if !self.contigs[i].is_empty() && !self.contigs[j].is_empty() {
                    if self.contigs[i].offset > self.contigs[j].offset {
                        self.contigs.swap(i, j);
                    }
                } else if self.contigs[i].is_empty() && !self.contigs[j].is_empty() {
                    self.contigs.swap(i, j);
                }
            }
        }
    }
}

impl Default for Assembler {
    fn default() -> Self {
        Self::new()
    }
}

// ========== Tests ==========

#[cfg(test)]
mod tests {
    use super::*;

    #[test_case]
    fn test_ring_buffer_basic() {
        let mut storage = [0u8; 16];
        let mut buf = RingBuffer::new(&mut storage);

        assert_eq!(buf.capacity(), 16);
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.window(), 16);
        assert!(buf.is_empty());
        assert!(!buf.is_full());

        // Enqueue
        let written = buf.enqueue_slice(&[1, 2, 3, 4]);
        assert_eq!(written, 4);
        assert_eq!(buf.len(), 4);
        assert_eq!(buf.window(), 12);

        // Dequeue
        let mut out = [0u8; 4];
        let read = buf.dequeue_slice(&mut out);
        assert_eq!(read, 4);
        assert_eq!(out, [1, 2, 3, 4]);
        assert_eq!(buf.len(), 0);
    }

    #[test_case]
    fn test_ring_buffer_wraparound() {
        let mut storage = [0u8; 8];
        let mut buf = RingBuffer::new(&mut storage);

        // Fill most of buffer
        buf.enqueue_slice(&[1, 2, 3, 4, 5]);
        assert_eq!(buf.len(), 5);

        // Dequeue some
        let mut tmp = [0u8; 3];
        buf.dequeue_slice(&mut tmp);
        assert_eq!(buf.len(), 2);
        assert_eq!(tmp, [1, 2, 3]);

        // Enqueue more (will wrap around)
        let written = buf.enqueue_slice(&[6, 7, 8, 9, 10, 11]);
        assert_eq!(written, 6);
        assert_eq!(buf.len(), 8);
        assert!(buf.is_full());

        // Dequeue all
        let mut all = [0u8; 8];
        buf.dequeue_slice(&mut all);
        assert_eq!(all, [4, 5, 6, 7, 8, 9, 10, 11]);
    }

    #[test_case]
    fn test_ring_buffer_peek() {
        let mut storage = [0u8; 16];
        let mut buf = RingBuffer::new(&mut storage);

        buf.enqueue_slice(&[1, 2, 3, 4, 5]);

        let mut peek = [0u8; 3];
        let read = buf.peek_slice(1, &mut peek);
        assert_eq!(read, 3);
        assert_eq!(peek, [2, 3, 4]);

        // Buffer unchanged
        assert_eq!(buf.len(), 5);
    }

    #[test_case]
    fn test_ring_buffer_dequeue_many() {
        let mut storage = [0u8; 16];
        let mut buf = RingBuffer::new(&mut storage);

        buf.enqueue_slice(&[1, 2, 3, 4, 5]);
        buf.dequeue_many(3);
        assert_eq!(buf.len(), 2);

        let mut out = [0u8; 2];
        buf.dequeue_slice(&mut out);
        assert_eq!(out, [4, 5]);
    }

    #[test_case]
    fn test_assembler_basic() {
        let mut asm = Assembler::new();

        assert!(asm.is_empty());
        assert_eq!(asm.front(), 0);

        // Add contiguous segment from start
        assert!(asm.add(0, 10));
        assert_eq!(asm.front(), 10);

        // Remove some
        asm.remove_front(5);
        assert_eq!(asm.front(), 5);
    }

    #[test_case]
    fn test_assembler_out_of_order() {
        let mut asm = Assembler::new();

        // Add segments out of order
        assert!(asm.add(10, 5)); // Segment at [10, 15)
        assert_eq!(asm.front(), 0); // Gap at start

        assert!(asm.add(20, 5)); // Segment at [20, 25)
        assert_eq!(asm.front(), 0);

        // Fill first gap
        assert!(asm.add(0, 5)); // Segment at [0, 5)
        assert_eq!(asm.front(), 5);

        // Fill middle gap
        assert!(asm.add(5, 5)); // Segment at [5, 10) - should coalesce
        assert_eq!(asm.front(), 15);

        // Fill last gap
        assert!(asm.add(15, 5)); // Segment at [15, 20) - should coalesce all
        assert_eq!(asm.front(), 25);
    }

    #[test_case]
    fn test_assembler_overlap() {
        let mut asm = Assembler::new();

        // Add overlapping segments
        assert!(asm.add(0, 10));
        assert!(asm.add(5, 10)); // Overlaps [5, 10) with first segment
        assert_eq!(asm.front(), 15); // Should merge to [0, 15)
    }

    #[test_case]
    fn test_assembler_adjacency() {
        let mut asm = Assembler::new();

        assert!(asm.add(0, 10));
        assert!(asm.add(10, 10)); // Adjacent to first
        assert_eq!(asm.front(), 20); // Should merge
    }

    #[test_case]
    fn test_assembler_full() {
        let mut asm = Assembler::new();

        // Fill all slots with non-overlapping segments
        assert!(asm.add(0, 5));
        assert!(asm.add(10, 5));
        assert!(asm.add(20, 5));
        assert!(asm.add(30, 5));

        // Try to add one more - should fail
        assert!(!asm.add(40, 5));
    }

    #[test_case]
    fn test_assembler_clear() {
        let mut asm = Assembler::new();

        asm.add(0, 10);
        asm.add(20, 10);
        assert!(!asm.is_empty());

        asm.clear();
        assert!(asm.is_empty());
        assert_eq!(asm.front(), 0);
    }
}
