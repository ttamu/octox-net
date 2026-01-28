use crate::error::{Error, Result};
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketHandle(usize);

impl SocketHandle {
    pub const fn new(index: usize) -> Self {
        Self(index)
    }

    pub const fn index(&self) -> usize {
        self.0
    }
}

pub struct SocketSet<T> {
    sockets: Vec<Option<T>>,
    capacity: usize,
}

impl<T> SocketSet<T> {
    pub const fn new(capacity: usize) -> Self {
        Self {
            sockets: Vec::new(),
            capacity,
        }
    }

    fn ensure_capacity(&mut self) {
        if self.sockets.len() < self.capacity {
            self.sockets.resize_with(self.capacity, || None);
        }
    }

    pub fn alloc(&mut self, socket: T) -> Result<SocketHandle> {
        self.ensure_capacity();

        for (index, slot) in self.sockets.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(socket);
                return Ok(SocketHandle::new(index));
            }
        }

        Err(Error::NoSocketAvailable)
    }

    pub fn free(&mut self, handle: SocketHandle) -> Result<()> {
        self.ensure_capacity();

        if handle.index() >= self.capacity {
            return Err(Error::InvalidSocketIndex);
        }

        self.sockets[handle.index()] = None;
        Ok(())
    }

    pub fn get(&self, handle: SocketHandle) -> Result<&T> {
        if handle.index() >= self.sockets.len() {
            return Err(Error::InvalidSocketIndex);
        }

        self.sockets[handle.index()]
            .as_ref()
            .ok_or(Error::InvalidSocketState)
    }

    pub fn get_mut(&mut self, handle: SocketHandle) -> Result<&mut T> {
        if handle.index() >= self.sockets.len() {
            return Err(Error::InvalidSocketIndex);
        }

        self.sockets[handle.index()]
            .as_mut()
            .ok_or(Error::InvalidSocketState)
    }

    pub fn iter(&self) -> impl Iterator<Item = (SocketHandle, &T)> {
        self.sockets.iter().enumerate().filter_map(|(index, slot)| {
            slot.as_ref()
                .map(|socket| (SocketHandle::new(index), socket))
        })
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = (SocketHandle, &mut T)> {
        self.sockets
            .iter_mut()
            .enumerate()
            .filter_map(|(index, slot)| {
                slot.as_mut()
                    .map(|socket| (SocketHandle::new(index), socket))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test_case]
    fn test_socket_handle() {
        let handle = SocketHandle::new(5);
        assert_eq!(handle.index(), 5);
    }

    #[test_case]
    fn test_socket_set_alloc() {
        let mut sockets = SocketSet::<u32>::new(4);
        let h1 = sockets.alloc(100).unwrap();
        let h2 = sockets.alloc(200).unwrap();

        assert_eq!(*sockets.get(h1).unwrap(), 100);
        assert_eq!(*sockets.get(h2).unwrap(), 200);
    }

    #[test_case]
    fn test_socket_set_free() {
        let mut sockets = SocketSet::<u32>::new(4);
        let handle = sockets.alloc(100).unwrap();
        sockets.free(handle).unwrap();

        assert!(sockets.get(handle).is_err());
    }

    #[test_case]
    fn test_socket_set_full() {
        let mut sockets = SocketSet::<u32>::new(2);
        sockets.alloc(1).unwrap();
        sockets.alloc(2).unwrap();

        let result = sockets.alloc(3);
        assert!(result.is_err());
    }

    #[test_case]
    fn test_socket_set_iter() {
        let mut sockets = SocketSet::<u32>::new(4);
        sockets.alloc(100).unwrap();
        sockets.alloc(200).unwrap();

        let count = sockets.iter().count();
        assert_eq!(count, 2);
    }
}
