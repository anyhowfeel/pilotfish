//! The refill and grow loop around a `pcap-parser` streaming reader, shared by both formats.

use pcap_parser::PcapBlockOwned;
use pcap_parser::PcapError;
use pcap_parser::traits::PcapReaderIterator;

use super::ReadError;
use super::fill::IoErrors;

pub(super) const INITIAL_BUFFER: usize = 128 * 1024;
/// A single block above this size is treated as damage, not allocated.
pub(super) const MAX_BLOCK: usize = 16 * 1024 * 1024;

pub(super) enum Step<T> {
    Skip,
    Item(T),
}

pub(super) fn map_error<I>(e: PcapError<I>, io: &IoErrors) -> ReadError {
    match e {
        PcapError::ReadError => ReadError::Io(io.take()),
        PcapError::UnexpectedEof | PcapError::Incomplete(_) => {
            ReadError::Truncated("the file ends inside a block".into())
        }
        PcapError::BufferTooSmall => ReadError::Truncated("a block is too large".into()),
        PcapError::HeaderNotRecognized => ReadError::UnknownFormat,
        PcapError::NomError(_, kind) | PcapError::OwnedNomError(_, kind) => {
            ReadError::Truncated(format!("malformed block ({kind:?})"))
        }
        PcapError::Eof => ReadError::Truncated("unexpected end of file".into()),
    }
}

/// After the first error or the end, every call returns `Ok(None)`.
pub(super) struct Stream<I> {
    reader: I,
    capacity: usize,
    io: IoErrors,
    done: bool,
}

impl<I: PcapReaderIterator> Stream<I> {
    pub fn new(reader: I, capacity: usize, io: IoErrors) -> Self {
        Self {
            reader,
            capacity,
            io,
            done: false,
        }
    }

    #[cfg(test)]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Feeds blocks to `handle` until it yields an item or the file ends.
    pub fn next<T>(
        &mut self,
        mut handle: impl FnMut(PcapBlockOwned<'_>) -> Result<Step<T>, ReadError>,
    ) -> Result<Option<T>, ReadError> {
        if self.done {
            return Ok(None);
        }
        let result = self.pump(&mut handle);
        if !matches!(result, Ok(Some(_))) {
            self.done = true;
        }
        result
    }

    fn pump<T>(
        &mut self,
        handle: &mut impl FnMut(PcapBlockOwned<'_>) -> Result<Step<T>, ReadError>,
    ) -> Result<Option<T>, ReadError> {
        loop {
            match self.reader.next() {
                Ok((used, block)) => {
                    let step = handle(block);
                    self.reader.consume(used);
                    if let Step::Item(item) = step? {
                        return Ok(Some(item));
                    }
                }
                Err(PcapError::Eof) => return Ok(None),
                Err(PcapError::Incomplete(_) | PcapError::BufferTooSmall) => self.fill_more()?,
                Err(e) => return Err(map_error(e, &self.io)),
            }
        }
    }

    /// Reads more input; when the buffer is full and nothing can be read, doubles it up to
    /// `MAX_BLOCK`.
    fn fill_more(&mut self) -> Result<(), ReadError> {
        let before = self.reader.data().len();
        if let Err(e) = self.reader.refill() {
            return Err(map_error(e, &self.io));
        }
        if self.reader.data().len() != before || self.reader.reader_exhausted() {
            return Ok(());
        }
        if self.capacity >= MAX_BLOCK {
            return Err(ReadError::Truncated("a block is larger than 16 MiB".into()));
        }
        let wanted = (self.capacity * 2).min(MAX_BLOCK);
        if self.reader.grow(wanted) {
            self.capacity = wanted;
        }
        Ok(())
    }
}
