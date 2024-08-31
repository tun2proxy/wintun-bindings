use crate::handle::UnsafeHandle;
use futures::{AsyncRead, AsyncWrite};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use windows_sys::Win32::{
    Foundation::{FALSE, HANDLE, WAIT_ABANDONED_0, WAIT_EVENT, WAIT_OBJECT_0},
    System::Threading::{WaitForMultipleObjects, INFINITE},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WaitingStopReason {
    Shutdown,
    Ready,
}

#[derive(Debug)]
enum ReadState {
    Waiting(Option<blocking::Task<WaitingStopReason>>),
    Idle,
    Closed,
}

pub struct AsyncSession {
    session: Arc<crate::session::Session>,
    read_state: ReadState,
}

impl From<Arc<crate::session::Session>> for AsyncSession {
    fn from(session: Arc<crate::session::Session>) -> Self {
        Self {
            session,
            read_state: ReadState::Idle,
        }
    }
}

impl Drop for AsyncSession {
    fn drop(&mut self) {
        self.session.shutdown().ok();
    }
}

impl AsyncSession {
    fn wait_for_read(read_event: UnsafeHandle<HANDLE>, shutdown_event: UnsafeHandle<HANDLE>) -> WaitingStopReason {
        const WAIT_OBJECT_1: WAIT_EVENT = WAIT_OBJECT_0 + 1;
        const WAIT_ABANDONED_1: WAIT_EVENT = WAIT_ABANDONED_0 + 1;
        let handles = [shutdown_event.0, read_event.0];
        match unsafe { WaitForMultipleObjects(handles.len() as u32, &handles as _, FALSE, INFINITE) } {
            WAIT_OBJECT_0 | WAIT_ABANDONED_0 => WaitingStopReason::Shutdown,
            WAIT_OBJECT_1 => WaitingStopReason::Ready,
            WAIT_ABANDONED_1 => panic!("Read event deleted unexpectedly"),
            e => panic!("WaitForMultipleObjects returned unexpected value {:?}", e),
        }
    }
}

impl AsyncRead for AsyncSession {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context, buf: &mut [u8]) -> Poll<std::io::Result<usize>> {
        loop {
            match &mut self.read_state {
                ReadState::Idle => match self.session.try_receive() {
                    Ok(Some(packet)) => {
                        let size = packet.bytes.len().min(buf.len());
                        buf[..size].copy_from_slice(&packet.bytes[..size]);
                        return Poll::Ready(Ok(size));
                    }
                    Ok(None) => {
                        let read_event = self.session.get_read_wait_event()?;
                        let shutdown_event = self.session.shutdown_event.get_handle();
                        self.read_state = ReadState::Waiting(Some(blocking::unblock(move || {
                            Self::wait_for_read(read_event, shutdown_event)
                        })));
                    }
                    Err(err) => return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, err))),
                },
                ReadState::Waiting(task) => {
                    let mut task = task.take().unwrap();
                    self.read_state = match Pin::new(&mut task).poll(cx) {
                        Poll::Ready(WaitingStopReason::Shutdown) => ReadState::Closed,
                        Poll::Ready(WaitingStopReason::Ready) => ReadState::Idle,
                        Poll::Pending => ReadState::Waiting(Some(task)),
                    };
                    if let ReadState::Waiting(_) = self.read_state {
                        return Poll::Pending;
                    }
                }
                ReadState::Closed => return Poll::Ready(Ok(0)),
            }
        }
    }
}

impl AsyncWrite for AsyncSession {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let packet = self.session.allocate_send_packet(buf.len() as _)?;
        packet.bytes.copy_from_slice(buf);
        self.session.send_packet(packet);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.session.shutdown()?;
        Poll::Ready(Ok(()))
    }
}
