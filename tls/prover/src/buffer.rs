use futures::{
    task::{AtomicWaker, Context, Poll},
    AsyncRead, AsyncWrite,
};
use std::{
    io::{Error, Read, Write},
    pin::Pin,
    sync::atomic::AtomicUsize,
};

pub struct ExchangeBuffer {
    request_buffer: AtomicByteBuffer,
    response_buffer: AtomicByteBuffer,
}

impl ExchangeBuffer {
    pub fn new() -> Self {
        Self {
            request_buffer: AtomicByteBuffer::new(4096),
            response_buffer: AtomicByteBuffer::new(4096),
        }
    }

    pub async fn make_request<T: Into<Vec<u8>>>(&self, _request: T) -> Result<(), BufferError> {
        todo!();
    }

    pub async fn receive_response<'a, T: From<&'a [u8]>>() -> Result<T, BufferError> {
        todo!();
    }
}

struct AtomicByteBuffer {
    buffer: Vec<u8>,
    read_mark: AtomicUsize,
    write_mark: AtomicUsize,
    read_waker: AtomicWaker,
    write_waker: AtomicWaker,
}

impl AtomicByteBuffer {
    pub fn new(size: usize) -> Self {
        Self {
            buffer: vec![0; size],
            read_mark: AtomicUsize::new(0),
            write_mark: AtomicUsize::new(0),
            read_waker: AtomicWaker::new(),
            write_waker: AtomicWaker::new(),
        }
    }

    unsafe fn raw_mut(&self) -> &mut [u8] {
        unsafe {
            let slice_start = self.buffer.as_ptr() as *mut u8;
            std::slice::from_raw_parts_mut(slice_start, self.buffer.len())
        }
    }

    fn increment_read_mark(&self) -> Result<(usize, usize), BufferError> {
        let out = self.increment_mark(&self.read_mark, &self.write_mark);
        if out.is_ok() {
            self.write_waker.wake();
        }
        out
    }

    fn increment_write_mark(&self) -> Result<(usize, usize), BufferError> {
        let out = self.increment_mark(&self.write_mark, &self.read_mark);
        if out.is_ok() {
            self.read_waker.wake();
        }
        out
    }

    fn increment_mark(
        &self,
        mark_to_increment: &AtomicUsize,
        until_mark: &AtomicUsize,
    ) -> Result<(usize, usize), BufferError> {
        let mti = mark_to_increment.load(std::sync::atomic::Ordering::Acquire);
        let um = until_mark.load(std::sync::atomic::Ordering::Relaxed);

        match mark_to_increment.compare_exchange_weak(
            mti,
            um,
            std::sync::atomic::Ordering::Release,
            std::sync::atomic::Ordering::Relaxed,
        ) {
            Ok(old_mark) => {
                if old_mark < um {
                    Ok((old_mark, um - old_mark))
                } else {
                    Ok((old_mark, um + self.buffer.len() - old_mark))
                }
            }
            Err(_) => Err(BufferError::NoProgress),
        }
    }
}

impl AsyncWrite for &AtomicByteBuffer {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        let atomic_byte_buffer = Pin::into_inner(self);
        match Write::write(atomic_byte_buffer, buf) {
            Ok(len) => Poll::Ready(Ok(len)),
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                atomic_byte_buffer.write_waker.register(cx.waker());
                Poll::Pending
            }
            _ => unreachable!(),
        }
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }
}

impl Write for &AtomicByteBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match (*self).increment_write_mark() {
            Ok((mark, len)) => {
                assert!(len <= buf.len());
                let buffer = unsafe { (*self).raw_mut() };
                let buffer_len = buffer.len();
                if mark + len < buffer_len {
                    _ = (&mut buffer[mark..mark + len]).write(buf);
                } else {
                    _ = (&mut buffer[mark..]).write(buf);
                    _ = (&mut buffer[..len - (buffer_len - mark)]).write(buf);
                }
                Ok(buf.len())
            }
            Err(BufferError::NoProgress) => Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "No progress was made",
            )),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl AsyncRead for &AtomicByteBuffer {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, Error>> {
        let atomic_byte_buffer = Pin::into_inner(self);
        match Read::read(atomic_byte_buffer, buf) {
            Ok(len) => Poll::Ready(Ok(len)),
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                atomic_byte_buffer.read_waker.register(cx.waker());
                Poll::Pending
            }
            _ => unreachable!(),
        }
    }
}

impl Read for &AtomicByteBuffer {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let buffer = &(*self).buffer;
        match (*self).increment_read_mark() {
            Ok((mark, len)) => {
                assert!(len <= buf.len());
                if mark + len < buffer.len() {
                    _ = (&buffer[mark..mark + len]).read(buf);
                } else {
                    _ = (&buffer[mark..]).read(buf);
                    _ = (&buffer[..len - (buffer.len() - mark)]).read(buf);
                }
                Ok(len)
            }
            Err(BufferError::NoProgress) => Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "No progress was made",
            )),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BufferError {
    #[error("No progress was made")]
    NoProgress,
}
