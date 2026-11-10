use std::{io, marker::PhantomData};

use futures_util::{SinkExt, StreamExt};
use serde::{Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf};
use tokio_util::codec::{FramedRead, FramedWrite, LinesCodec, LinesCodecError};

use crate::MAX_FRAME_BYTES;

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("IPC I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("IPC frame exceeds {MAX_FRAME_BYTES} bytes")]
    TooLarge,
    #[error("malformed IPC frame: {0}")]
    Json(#[from] serde_json::Error),
}

impl From<LinesCodecError> for FrameError {
    fn from(e: LinesCodecError) -> Self {
        match e {
            LinesCodecError::MaxLineLengthExceeded => Self::TooLarge,
            LinesCodecError::Io(e) => Self::Io(e),
        }
    }
}

/// Reads newline-delimited JSON frames of type `T`.
#[derive(Debug)]
pub struct FrameReader<R, T> {
    inner: FramedRead<R, LinesCodec>,
    _frame: PhantomData<fn() -> T>,
}

impl<R: AsyncRead + Unpin, T: DeserializeOwned> FrameReader<R, T> {
    pub fn new(reader: R) -> Self {
        Self { inner: FramedRead::new(reader, LinesCodec::new_with_max_length(MAX_FRAME_BYTES)), _frame: PhantomData }
    }

    /// `Ok(None)` on a clean end of stream.
    pub async fn next(&mut self) -> Result<Option<T>, FrameError> {
        match self.inner.next().await {
            None => Ok(None),
            Some(line) => Ok(Some(serde_json::from_str(&line?)?)),
        }
    }
}

/// Writes newline-delimited JSON frames of type `T`.
#[derive(Debug)]
pub struct FrameWriter<W, T> {
    inner: FramedWrite<W, LinesCodec>,
    _frame: PhantomData<fn(T)>,
}

impl<W: AsyncWrite + Unpin, T: Serialize> FrameWriter<W, T> {
    pub fn new(writer: W) -> Self {
        Self { inner: FramedWrite::new(writer, LinesCodec::new_with_max_length(MAX_FRAME_BYTES)), _frame: PhantomData }
    }

    pub async fn send(&mut self, frame: &T) -> Result<(), FrameError> {
        // serde_json never emits raw newlines, so one frame is one line.
        let line = serde_json::to_string(frame)?;
        if line.len() > MAX_FRAME_BYTES {
            return Err(FrameError::TooLarge);
        }
        self.inner.send(line).await?;
        Ok(())
    }
}

/// Splits a stream into a typed reader and writer.
pub fn split<S, In, Out>(stream: S) -> (FrameReader<ReadHalf<S>, In>, FrameWriter<WriteHalf<S>, Out>)
where
    S: AsyncRead + AsyncWrite,
    In: DeserializeOwned,
    Out: Serialize,
{
    let (r, w) = tokio::io::split(stream);
    (FrameReader::new(r), FrameWriter::new(w))
}
