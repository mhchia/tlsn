use std::{cmp, collections::VecDeque, io, io::Read};

/// This is a byte buffer that is built from a vector
/// of byte vectors.  This avoids extra copies when
/// appending a new byte vector, at the expense of
/// more complexity when reading out.
pub(crate) struct ChunkVecBuffer {
    chunks: VecDeque<Vec<u8>>,
    limit: Option<usize>,
    read_notify: tokio::sync::Notify,
    write_notify: tokio::sync::Notify,
}

impl ChunkVecBuffer {
    pub(crate) fn new(limit: Option<usize>) -> Self {
        Self {
            chunks: VecDeque::new(),
            limit,
            read_notify: tokio::sync::Notify::new(),
            write_notify: tokio::sync::Notify::new(),
        }
    }

    /// Sets the upper limit on how many bytes this
    /// object can store.
    ///
    /// Setting a lower limit than the currently stored
    /// data is not an error.
    ///
    /// A [`None`] limit is interpreted as no limit.
    pub(crate) fn set_limit(&mut self, new_limit: Option<usize>) {
        self.limit = new_limit;
    }

    /// If we're empty
    pub(crate) fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }

    /// How many bytes we're storing
    pub(crate) fn len(&self) -> usize {
        let mut len = 0;
        for ch in &self.chunks {
            len += ch.len();
        }
        len
    }

    /// For a proposed append of `len` bytes, how many
    /// bytes should we actually append to adhere to the
    /// currently set `limit`?
    pub(crate) fn apply_limit(&self, len: usize) -> usize {
        if let Some(limit) = self.limit {
            let space = limit.saturating_sub(self.len());
            cmp::min(len, space)
        } else {
            len
        }
    }

    /// Append a copy of `bytes`, perhaps a prefix if
    /// we're near the limit.
    pub(crate) fn append_limited_copy(&mut self, bytes: &[u8]) -> usize {
        let take = self.apply_limit(bytes.len());
        self.append(bytes[..take].to_vec());
        if !bytes.is_empty() {
            self.write_notify.notify_one();
        }
        take
    }

    /// Take and append the given `bytes`.
    pub(crate) fn append(&mut self, bytes: Vec<u8>) -> usize {
        let len = bytes.len();

        if !bytes.is_empty() {
            self.chunks.push_back(bytes);
            self.write_notify.notify_one();
        }

        len
    }

    /// Take one of the chunks from this object.  This
    /// function panics if the object `is_empty`.
    pub(crate) fn pop(&mut self) -> Option<Vec<u8>> {
        let chunk = self.chunks.pop_front();
        if chunk.is_some() {
            self.read_notify.notify_one();
        }
        chunk
    }

    /// Read data out of this object, writing it into `buf`
    /// and returning how many bytes were written there.
    pub(crate) fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut offs = 0;

        while offs < buf.len() && !self.is_empty() {
            let used = self.chunks[0].as_slice().read(&mut buf[offs..])?;

            self.consume(used);
            offs += used;
        }
        if offs > 0 {
            self.read_notify.notify_one();
        }

        Ok(offs)
    }

    #[cfg(read_buf)]
    /// Read data out of this object, writing it into `buf`.
    pub(crate) fn read_buf(&mut self, buf: &mut io::ReadBuf<'_>) -> io::Result<()> {
        if !self.is_empty() && buf.remaining() > 0 {
            self.read_notify.notify_one();
        }
        while !self.is_empty() && buf.remaining() > 0 {
            let chunk = self.chunks[0].as_slice();
            let used = std::cmp::min(chunk.len(), buf.remaining());
            buf.append(&chunk[..used]);
            self.consume(used);
        }

        Ok(())
    }

    fn consume(&mut self, mut used: usize) {
        while let Some(mut buf) = self.chunks.pop_front() {
            if used < buf.len() {
                self.chunks.push_front(buf.split_off(used));
                break;
            } else {
                used -= buf.len();
            }
        }
    }

    /// Read data out of this object, passing it `wr`
    pub(crate) fn write_to(&mut self, wr: &mut dyn io::Write) -> io::Result<usize> {
        if self.is_empty() {
            return Ok(0);
        }

        let mut bufs = [io::IoSlice::new(&[]); 64];
        for (iov, chunk) in bufs.iter_mut().zip(self.chunks.iter()) {
            *iov = io::IoSlice::new(chunk);
        }
        let len = cmp::min(bufs.len(), self.chunks.len());
        let used = wr.write_vectored(&bufs[..len])?;
        self.consume(used);
        if used > 0 {
            self.write_notify.notify_one();
        }
        Ok(used)
    }
}

#[cfg(test)]
mod test {
    use super::ChunkVecBuffer;

    #[test]
    fn short_append_copy_with_limit() {
        let mut cvb = ChunkVecBuffer::new(Some(12));
        assert_eq!(cvb.append_limited_copy(b"hello"), 5);
        assert_eq!(cvb.append_limited_copy(b"world"), 5);
        assert_eq!(cvb.append_limited_copy(b"hello"), 2);
        assert_eq!(cvb.append_limited_copy(b"world"), 0);

        let mut buf = [0u8; 12];
        assert_eq!(cvb.read(&mut buf).unwrap(), 12);
        assert_eq!(buf.to_vec(), b"helloworldhe".to_vec());
    }

    #[cfg(read_buf)]
    #[test]
    fn read_buf() {
        use std::{io::ReadBuf, mem::MaybeUninit};

        {
            let mut cvb = ChunkVecBuffer::new(None);
            cvb.append(b"test ".to_vec());
            cvb.append(b"fixture ".to_vec());
            cvb.append(b"data".to_vec());

            let mut buf = [MaybeUninit::<u8>::uninit(); 8];
            let mut buf = ReadBuf::uninit(&mut buf);
            cvb.read_buf(&mut buf).unwrap();
            assert_eq!(buf.filled(), b"test fix");
            buf.clear();
            cvb.read_buf(&mut buf).unwrap();
            assert_eq!(buf.filled(), b"ture dat");
            buf.clear();
            cvb.read_buf(&mut buf).unwrap();
            assert_eq!(buf.filled(), b"a");
        }

        {
            let mut cvb = ChunkVecBuffer::new(None);
            cvb.append(b"short message".to_vec());

            let mut buf = [MaybeUninit::<u8>::uninit(); 1024];
            let mut buf = ReadBuf::uninit(&mut buf);
            cvb.read_buf(&mut buf).unwrap();
            assert_eq!(buf.filled(), b"short message");
        }
    }
}
