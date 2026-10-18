//! Envelope framing over QUIC streams: read/write with the §5 rules —
//! strict size cap, major-version mismatch closes the connection, unknown
//! kinds are handed up so the caller can skip them.

use serde::{de::DeserializeOwned, Serialize};

use crate::envelope::{
    decode_payload, max_payload_for, Envelope, EnvelopeError, Kind, HEADER_LEN,
};

#[derive(Debug, thiserror::Error)]
pub enum StreamError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("stream closed")]
    Closed,
    #[error("envelope: {0}")]
    Envelope(#[from] EnvelopeError),
    #[error("decode: {0}")]
    Decode(#[from] bincode::Error),
}

/// Write one framed control message.
pub async fn write_msg<T: Serialize>(
    tx: &mut quinn::SendStream,
    kind: Kind,
    msg: &T,
) -> Result<(), StreamError> {
    let bytes = crate::envelope::encode_msg(kind, msg)?;
    tx.write_all(&bytes).await.map_err(io_err)?;
    Ok(())
}

/// Write an already-encoded envelope verbatim.
///
/// The RPC layer encodes its own frames (it nests a typed body inside a
/// request), so it needs a way to hand finished bytes to whichever task
/// owns the send stream rather than encoding again.
pub async fn write_bytes(
    tx: &mut quinn::SendStream,
    bytes: &[u8],
) -> Result<(), StreamError> {
    tx.write_all(bytes).await.map_err(io_err)?;
    Ok(())
}

/// Read one framed control message (header first, then exactly `len`).
///
/// **Not cancel-safe.** The header and payload arrive in separate reads,
/// and bytes already taken from the stream live only in this future: drop
/// it part-way (a losing `tokio::select!` branch) and they are gone, the
/// next call starts reading mid-message, and the stream is desynced for
/// good. Await it to completion, from a task of its own if anything else
/// must happen meanwhile. A `timeout` around it is fine only when expiry
/// abandons the stream.
pub async fn read_envelope(rx: &mut quinn::RecvStream) -> Result<Envelope, StreamError> {
    read_envelope_max(rx, u32::MAX).await
}

/// [`read_envelope`] with a caller-chosen payload cap below the per-kind
/// one — for a message read before the peer has authenticated (`Hello`),
/// where a 1 MiB allowance is 1 MiB a stranger can make us hold. The
/// same cancel-safety caveat applies.
pub async fn read_envelope_max(
    rx: &mut quinn::RecvStream,
    max: u32,
) -> Result<Envelope, StreamError> {
    let mut header = [0u8; HEADER_LEN];
    rx.read_exact(&mut header).await.map_err(read_exact_err)?;
    // Validate the header before allocating anything.
    match Envelope::decode(&header) {
        Err(EnvelopeError::Truncated(_)) => {}
        Err(e) => return Err(e.into()),
        Ok(_) => {}
    }
    let kind = u16::from_be_bytes([header[2], header[3]]);
    let len = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
    if header[0] != crate::envelope::PROTO_MAJOR {
        return Err(EnvelopeError::IncompatibleMajor(header[0]).into());
    }
    if len > max_payload_for(kind) || len > max {
        return Err(EnvelopeError::TooLarge(len).into());
    }
    // Grow with what actually arrives rather than trusting the declared
    // length up front: a header alone must not buy a large allocation.
    let len = len as usize;
    let mut payload = Vec::with_capacity(len.min(READ_CHUNK));
    while payload.len() < len {
        let want = (len - payload.len()).min(READ_CHUNK);
        match rx.read_chunk(want, true).await {
            Ok(Some(chunk)) => payload.extend_from_slice(&chunk.bytes),
            Ok(None) => return Err(StreamError::Closed),
            Err(e) => return Err(StreamError::Io(std::io::Error::other(e))),
        }
    }
    Ok(Envelope {
        major: header[0],
        minor: header[1],
        kind,
        payload,
    })
}

/// Largest single read while filling a payload, and the most allocated
/// ahead of the data that fills it.
const READ_CHUNK: usize = 64 * 1024;

fn read_exact_err(e: quinn::ReadExactError) -> StreamError {
    match e {
        quinn::ReadExactError::FinishedEarly(_) => StreamError::Closed,
        quinn::ReadExactError::ReadError(e) => StreamError::Io(std::io::Error::other(e)),
    }
}

pub fn parse<T: DeserializeOwned>(env: &Envelope) -> Result<T, StreamError> {
    Ok(decode_payload(&env.payload)?)
}

fn io_err(e: quinn::WriteError) -> StreamError {
    match e {
        quinn::WriteError::ClosedStream | quinn::WriteError::Stopped(_) => StreamError::Closed,
        other => StreamError::Io(std::io::Error::other(other)),
    }
}
