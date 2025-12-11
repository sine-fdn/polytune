use std::{
    borrow::Cow,
    fs::File,
    io::{BufReader, BufWriter, Seek, SeekFrom, Write},
    path::Path,
    sync::Arc,
};

use bincode::{
    config::legacy,
    error::{DecodeError, EncodeError},
    serde::{decode_from_std_read, encode_into_std_write},
};
use serde::{Serialize, de::DeserializeOwned};
use tempfile::tempfile_in;
use tracing::debug;

/// Abstraction over a chunked buffer backed by a temporary file or in-memory
///
/// This type can be used to store intermediate data serialized in chunks in a temporary file.
/// If the [`FileOrMemBuf::new`] is passed a [`Path`] to a directory, a temporary file will be
/// created in that directory. Subsequent [`FileOrMemBuf::write_chunk`] calls will serialize the
/// chunk into the file. Once all data is written, [`FileOrMemBuf::iter`] can be used to create
/// an iterator for the temporary file (or the in-memory Vec if no directory was provided).
/// Only ever one of the previously written chunks will be held in memory.
///
/// When backed by a temporary file, the [`FileOrMemBuf`] will print the bytes written as a
/// tracing debug event when dropped.
pub(crate) enum FileOrMemBuf<T> {
    ChunkedTmpFile { write: TrackWrite },
    Memory { data: Vec<T> },
}

/// Wraps a BufWriter<Arc<File>> to track the number of bytes written.
///
/// Logs the number of bytes written as a `debug` tracing event when dropped.
pub(crate) struct TrackWrite {
    written: usize,
    writer: BufWriter<Arc<File>>,
}

pub(crate) enum Iter<'a, T> {
    ChunkedTmpFile {
        read: BufReader<Arc<File>>,
        chunk_iter: std::vec::IntoIter<T>,
    },
    Memory {
        iter: std::slice::Iter<'a, T>,
    },
}

pub(crate) enum ChunkIter<'a, T> {
    ChunkedTmpFile { read: BufReader<Arc<File>> },
    Memory { iter: std::slice::Chunks<'a, T> },
}

impl<T> FileOrMemBuf<T> {
    /// Create an optionally temp file backed buffer.
    ///
    /// The capacity is only used for the in-memory buf if `dir` is `None`.
    pub(crate) fn new(dir: Option<&Path>, capacity: usize) -> std::io::Result<Self> {
        if let Some(dir) = dir {
            let file = tempfile_in(dir)?;
            let write = TrackWrite::new(file);
            Ok(Self::ChunkedTmpFile { write })
        } else {
            Ok(Self::Memory {
                data: Vec::with_capacity(capacity),
            })
        }
    }

    /// Create an iterator for the [`FileOrMemBuf`].
    ///
    /// For the [`FileOrMemBuf::ChunkedTmpFile`] variant, the matching iterator
    /// will only read one of the written chunks (+ potentially the default capacity of
    /// a BufReader) and keep it in memory until it is iterated over. Then the next
    /// chunk is loaded.
    pub(crate) fn iter(&mut self) -> std::io::Result<Iter<'_, T>> {
        match self {
            FileOrMemBuf::ChunkedTmpFile { write } => {
                write.flush()?;
                let mut file = write.clone_file();
                file.rewind()?;
                let read = BufReader::new(file);
                Ok(Iter::ChunkedTmpFile {
                    read,
                    chunk_iter: Default::default(),
                })
            }
            FileOrMemBuf::Memory { data } => Ok(Iter::Memory { iter: data.iter() }),
        }
    }

    /// Iterator over the chunks stored in the file or a chunk iterator for the in-memory buf.
    ///
    /// The `chunks` parameter is only used in the [`FileOrMemBuf::Memory`] case, otherwise the
    /// exact chunks that were written to the file by [`FileOrMemBuf::write_chunk`] are returned.
    pub(crate) fn chunks(&mut self, size: usize) -> std::io::Result<ChunkIter<'_, T>> {
        match self {
            FileOrMemBuf::ChunkedTmpFile { write } => {
                write.flush()?;
                let mut file = write.clone_file();
                file.rewind()?;
                let read = BufReader::new(file);
                Ok(ChunkIter::ChunkedTmpFile { read })
            }
            FileOrMemBuf::Memory { data } => Ok(ChunkIter::Memory {
                iter: data.chunks(size),
            }),
        }
    }
}

impl<T> Default for FileOrMemBuf<T> {
    fn default() -> Self {
        Self::Memory { data: vec![] }
    }
}

impl<T: Serialize + Clone> FileOrMemBuf<T> {
    /// Write a chunk to the temporary file or in-memory buffer.
    pub(crate) fn write_chunk(&mut self, chunk: &[T]) -> Result<(), EncodeError> {
        match self {
            FileOrMemBuf::ChunkedTmpFile { write, .. } => {
                encode_into_std_write(chunk, write, legacy())?;
            }
            FileOrMemBuf::Memory { data } => {
                data.extend_from_slice(chunk);
            }
        }
        Ok(())
    }
}

impl<'a, T: DeserializeOwned + Clone> Iterator for Iter<'a, T> {
    type Item = Result<T, DecodeError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Iter::ChunkedTmpFile { read, chunk_iter } => {
                if let Some(gate) = chunk_iter.next() {
                    return Some(Ok(gate));
                }
                match decode_from_std_read::<Vec<T>, _, _>(read, legacy()) {
                    Ok(chunk) => {
                        *chunk_iter = chunk.into_iter();
                        self.next()
                    }
                    Err(err) => {
                        if let DecodeError::Io { inner: io, .. } = &err
                            && std::io::ErrorKind::UnexpectedEof == io.kind()
                        {
                            return None;
                        }

                        Some(Err(err))
                    }
                }
            }
            Iter::Memory { iter } => iter.next().map(|e| Ok(e.clone())),
        }
    }
}

// The drop impl ensures that we can create an iterator, and afterwards continue
// writing to the end of the file and don't overwrite existing content.
impl<'a, T> Drop for Iter<'a, T> {
    fn drop(&mut self) {
        if let Self::ChunkedTmpFile { read, .. } = self {
            read.get_mut()
                .seek(SeekFrom::End(0))
                .expect("unable to reset seek position");
        }
    }
}

impl<'a, T: DeserializeOwned + Clone> Iterator for ChunkIter<'a, T> {
    type Item = Result<Cow<'a, [T]>, DecodeError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            ChunkIter::ChunkedTmpFile { read } => {
                match decode_from_std_read::<Vec<T>, _, _>(read, legacy()) {
                    Ok(chunk) => Some(Ok(Cow::Owned(chunk))),
                    Err(err) => {
                        if let DecodeError::Io { inner: io, .. } = &err
                            && std::io::ErrorKind::UnexpectedEof == io.kind()
                        {
                            return None;
                        }
                        Some(Err(err))
                    }
                }
            }
            ChunkIter::Memory { iter } => iter.next().map(|e| Ok(Cow::Borrowed(e))),
        }
    }
}

impl TrackWrite {
    pub(crate) fn new(file: File) -> Self {
        Self {
            written: 0,
            writer: BufWriter::new(Arc::new(file)),
        }
    }

    pub(crate) fn clone_file(&self) -> Arc<File> {
        Arc::clone(self.writer.get_ref())
    }
}

impl Write for TrackWrite {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let bytes = self.writer.write(buf)?;
        self.written += bytes;
        Ok(bytes)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }

    fn write_vectored(&mut self, bufs: &[std::io::IoSlice<'_>]) -> std::io::Result<usize> {
        let bytes = self.writer.write_vectored(bufs)?;
        self.written += bytes;
        Ok(bytes)
    }

    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        self.writer.write_all(buf)?;
        self.written += buf.len();
        Ok(())
    }
}

impl<T> Drop for FileOrMemBuf<T> {
    fn drop(&mut self) {
        if let Self::ChunkedTmpFile { write } = self {
            debug!(bytes_written = write.written, "bytes written to tmp file")
        }
    }
}

impl<'a, T> Drop for ChunkIter<'a, T> {
    fn drop(&mut self) {
        if let Self::ChunkedTmpFile { read, .. } = self {
            read.get_mut()
                .seek(SeekFrom::End(0))
                .expect("unable to reset seek position");
        }
    }
}
