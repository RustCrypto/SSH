//! Shared decoder for SSH protocol data types.

use crate::{Decode, Error, Reader, Result};
use core::{fmt, str};

/// Decoder for SSH protocol data types over a byte [`Reader`].
///
/// Construct a decoder with [`Reader::into_decoder`] or the [`From`] conversion.
///
/// All nested decoding uses the same decoder type, with enclosing bounds stored on the call
/// stack. Neither nesting nor decoding from Base64 or PEM requires a heap allocation.
///
/// A failed read or nested decoding operation invalidates the decoder. Subsequent reads and
/// completion checks return [`Error::Failed`]. The underlying reader is not rewound on errors.
///
/// # Example
/// ```
/// use ssh_encoding::{Decode, Reader};
///
/// let mut decoder = [0, 0, 0, 42].as_slice().into_decoder();
/// let value = u32::decode(&mut decoder)?;
/// assert_eq!(decoder.finish(value)?, 42);
/// # Ok::<(), ssh_encoding::Error>(())
/// ```
pub struct Decoder<R> {
    /// Underlying byte reader.
    reader: R,

    /// Position in the decoded input.
    position: usize,

    /// End of the currently active decoding scope.
    end: usize,

    /// Whether a read or nested decoding operation failed.
    failed: bool,
}

impl<R: Reader> Decoder<R> {
    /// Create a decoder which owns the given reader.
    #[must_use]
    pub fn new(reader: R) -> Self {
        let end = reader.remaining_len();
        Self {
            reader,
            position: 0,
            end,
            failed: false,
        }
    }

    /// Read enough bytes to exactly fill `out`, without crossing the active scope's boundary.
    ///
    /// # Errors
    /// - Returns [`Error::Failed`] if the decoder has already failed.
    /// - Returns [`Error::Length`] if `out` exceeds the remaining length.
    /// - Propagates errors returned from [`Reader::read`].
    pub fn read<'o>(&mut self, out: &'o mut [u8]) -> Result<&'o [u8]> {
        if self.failed {
            return Err(Error::Failed);
        }

        if out.len() > self.remaining_len() {
            self.failed = true;
            return Err(Error::Length);
        }

        // Avoid calling streaming decoders for empty reads.
        if out.is_empty() {
            return Ok(out);
        }

        let len = out.len();
        match self.reader.read(out) {
            Ok(bytes) => {
                self.position += len;
                Ok(bytes)
            }
            Err(err) => {
                self.failed = true;
                Err(err)
            }
        }
    }

    /// Get the number of decoded bytes remaining in the active scope.
    #[must_use]
    pub fn remaining_len(&self) -> usize {
        self.end - self.position
    }

    /// Have all bytes in the active scope been consumed?
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.remaining_len() == 0
    }

    /// Decode exactly `len` bytes within a nested scope.
    ///
    /// The callback receives the same decoder type with its bounds temporarily narrowed.
    /// It must consume the entire scope before returning successfully. Enclosing bounds are
    /// restored on success, error, or unwinding, without rewinding the underlying reader.
    ///
    /// # Errors
    /// - Returns [`Error::Failed`] if the decoder has already failed.
    /// - Returns [`Error::Length`] if `len` exceeds the remaining length.
    /// - Returns [`Error::TrailingData`] if the callback leaves unread bytes.
    /// - Propagates errors returned from the callback.
    pub fn read_nested<T, E, F>(&mut self, len: usize, f: F) -> core::result::Result<T, E>
    where
        E: From<Error>,
        F: FnOnce(&mut Self) -> core::result::Result<T, E>,
    {
        let mut scope = self.enter_nested(len)?;
        let value = f(scope.decoder)?;
        scope.decoder.ensure_finished()?;
        scope.completed = true;
        Ok(value)
    }

    /// Decode a `uint32` length prefix, then decode its body in a nested scope.
    ///
    /// # Errors
    /// Propagates errors decoding the prefix or returned by [`Decoder::read_nested`].
    pub fn read_prefixed<T, E, F>(&mut self, f: F) -> core::result::Result<T, E>
    where
        E: From<Error>,
        F: FnOnce(&mut Self) -> core::result::Result<T, E>,
    {
        let len = usize::decode(self).inspect_err(|_| self.failed = true)?;
        self.read_nested(len, f)
    }

    /// Decodes `[u8]` from `byte[n]` as described in [RFC4251 § 5]:
    ///
    /// > A byte represents an arbitrary 8-bit value (octet).  Fixed length
    /// > data is sometimes represented as an array of bytes, written
    /// > `byte[n]`, where n is the number of bytes in the array.
    ///
    /// Storage for the byte array must be provided as mutable byte slice in order to accommodate
    /// `no_alloc` use cases.
    ///
    /// The [`Decode`] impl on `Vec<u8>` can be used to allocate a buffer for the result.
    ///
    /// [RFC4251 § 5]: https://datatracker.ietf.org/doc/html/rfc4251#section-5
    ///
    /// # Errors
    /// - Returns [`Error::Length`] if `out` is too small to accommodate the full `byte[n]`.
    /// - Propagates errors returned from [`Decoder::read`].
    pub fn read_byten<'o>(&mut self, out: &'o mut [u8]) -> Result<&'o [u8]> {
        self.read_prefixed(|reader| {
            let slice = out.get_mut(..reader.remaining_len()).ok_or(Error::Length)?;
            reader.read(slice)?;
            Ok(&*slice)
        })
    }

    /// Decode a `string` as described in [RFC4251 § 5]:
    ///
    /// > Arbitrary length binary string.  Strings are allowed to contain
    /// > arbitrary binary data, including null characters and 8-bit
    /// > characters.  They are stored as a uint32 containing its length
    /// > (number of bytes that follow) and zero (= empty string) or more
    /// > bytes that are the value of the string.  Terminating null
    /// > characters are not used.
    /// >
    /// > Strings are also used to store text.  In that case, US-ASCII is
    /// > used for internal names, and ISO-10646 UTF-8 for text that might
    /// > be displayed to the user.  The terminating null character SHOULD
    /// > NOT normally be stored in the string.  For example: the US-ASCII
    /// > string "testing" is represented as 00 00 00 07 t e s t i n g.  The
    /// > UTF-8 mapping does not alter the encoding of US-ASCII characters.
    ///
    /// Storage for the string data must be provided as mutable byte slice in order to accommodate
    /// `no_alloc` use cases.
    ///
    /// The [`Decode`] impl on `String` can be used to allocate a buffer for the result.
    ///
    /// [RFC4251 § 5]: https://datatracker.ietf.org/doc/html/rfc4251#section-5
    ///
    /// # Errors
    /// - Propagates errors returned from [`Decoder::read_byten`].
    /// - Returns [`Error::CharacterEncoding`] if the data is not valid UTF-8.
    pub fn read_string<'o>(&mut self, buf: &'o mut [u8]) -> Result<&'o str> {
        Ok(str::from_utf8(self.read_byten(buf)?)?)
    }

    /// Drain the given number of bytes from the reader, discarding them.
    ///
    /// # Errors
    /// Propagates errors returned from [`Decoder::read`].
    pub fn drain(&mut self, n_bytes: usize) -> Result<()> {
        let mut byte = [0];
        for _ in 0..n_bytes {
            self.read(&mut byte)?;
        }
        Ok(())
    }

    /// Decode a `u32` length prefix, and then drain the length of the body.
    ///
    /// Upon success, returns the number of bytes drained sans the length of the `u32` length prefix
    /// (4-bytes).
    ///
    /// # Errors
    /// - Propagates errors returned from [`Decoder::read_prefixed`].
    /// - Propagates errors returned from [`Decoder::drain`].
    pub fn drain_prefixed(&mut self) -> Result<usize> {
        self.read_prefixed(|reader| {
            let len = reader.remaining_len();
            reader.drain(len)?;
            Ok(len)
        })
    }

    /// Ensure that decoding is finished.
    ///
    /// # Errors
    /// - Returns [`Error::Failed`] if the decoder has already failed.
    /// - Returns [`Error::TrailingData`] if there is data remaining in the decoder.
    pub fn ensure_finished(&self) -> Result<()> {
        if self.failed {
            Err(Error::Failed)
        } else if self.is_finished() {
            Ok(())
        } else {
            Err(Error::TrailingData {
                remaining: self.remaining_len(),
            })
        }
    }

    /// Finish decoding, returning the given value if there is no remaining data.
    ///
    /// # Errors
    /// - Returns [`Error::Failed`] if the decoder has already failed.
    /// - Returns [`Error::TrailingData`] if there is data remaining in the decoder.
    pub fn finish<T>(self, value: T) -> Result<T> {
        self.ensure_finished()?;
        Ok(value)
    }

    /// Enter a nested scope, keeping setup independent of the callback type.
    fn enter_nested(&mut self, len: usize) -> Result<NestedScope<'_, R>> {
        if self.failed {
            return Err(Error::Failed);
        }

        if len > self.remaining_len() {
            self.failed = true;
            return Err(Error::Length);
        }

        let outer_end = self.end;
        self.end = self.position + len;
        Ok(NestedScope {
            decoder: self,
            outer_end,
            completed: false,
        })
    }
}

impl<R: Reader> From<R> for Decoder<R> {
    fn from(reader: R) -> Self {
        Self::new(reader)
    }
}

impl<R: Reader> fmt::Debug for Decoder<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Decoder")
            .field("position", &self.position)
            .field("remaining_len", &self.remaining_len())
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}

/// Restores enclosing bounds on every exit path without introducing another reader type.
struct NestedScope<'a, R> {
    decoder: &'a mut Decoder<R>,
    outer_end: usize,
    completed: bool,
}

impl<R> Drop for NestedScope<'_, R> {
    fn drop(&mut self) {
        self.decoder.end = self.outer_end;
        if !self.completed {
            self.decoder.failed = true;
        }
    }
}
