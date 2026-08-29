//! Envelope framing over QUIC streams: read/write with the §5 rules —
//! strict size cap, major-version mismatch closes the connection, unknown
//! kinds are handed up so the caller can skip them.

use serde::{de::DeserializeOwned, Serialize};

use crate::envelope::{
    decode_payload, Envelope, EnvelopeError, Kind, HEADER_LEN, MAX_PAYLOAD,
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
pub async fn read_envelope(rx: &mut quinn::RecvStream) -> Result<Envelope, StreamError> {
    let mut header = [0u8; HEADER_LEN];
    rx.read_exact(&mut header).await.map_err(|e| match e {
        quinn::ReadExactError::FinishedEarly(_) => StreamError::Closed,
        quinn::ReadExactError::ReadError(e) => StreamError::Io(std::io::Error::other(e)),
    })?;
    // Validate the header before allocating anything.
    match Envelope::decode(&header) {
        Err(EnvelopeError::Truncated(_)) => {}
        Err(e) => return Err(e.into()),
        Ok(_) => {}
    }
    let len = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
    if header[0] != crate::envelope::PROTO_MAJOR {
        return Err(EnvelopeError::IncompatibleMajor(header[0]).into());
    }
    if len > MAX_PAYLOAD {
        return Err(EnvelopeError::TooLarge(len).into());
    }
    let mut payload = vec![0u8; len as usize];
    if len > 0 {
        rx.read_exact(&mut payload).await.map_err(|e| match e {
            quinn::ReadExactError::FinishedEarly(_) => StreamError::Closed,
            quinn::ReadExactError::ReadError(e) => StreamError::Io(std::io::Error::other(e)),
        })?;
    }
    Ok(Envelope {
        major: header[0],
        minor: header[1],
        kind: u16::from_be_bytes([header[2], header[3]]),
        payload,
    })
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
