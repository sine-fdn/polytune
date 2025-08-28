use std::{
    borrow::Cow,
    fs::File,
    io::{BufReader, BufWriter, Seek, SeekFrom, Write},
    path::Path,
    sync::Arc,
};

use bincode::Options;
use serde::{Serialize, de::DeserializeOwned};
use tempfile::tempfile_in;

/// Abstraction over a chunked buffer backed by a temporary file or in-memory
///
/// This type can be used to store intermediate data serialized in chunks in a temporary file.
/// If the [`MaybeFileBuf::new`] is passed a [`Path`] to a directory, a temporary file will be
/// created in that directory. Subsequent [`MaybeFileBuf::write_chunk`] calls will serialize the
/// chunk into the file. Once all data is written, [`MaybeFileBuf::iter`] can be used to create
/// an iterator for the temporary file (or the in-memory Vec if no directory was provided).
/// Only ever one of the previously written chunks will be held in memory.
pub(crate) enum MaybeFileBuf<T> {
    ChunkedTmpFile { write: BufWriter<Arc<File>> },
    Memory { data: Vec<T> },
}

pub(crate) enum MaybeFileBufIter<'a, T> {
    ChunkedTmpFile {
        read: BufReader<Arc<File>>,
        chunk_iter: std::vec::IntoIter<T>,
    },
    Memory {
        iter: std::slice::Iter<'a, T>,
    },
}

pub(crate) enum MaybeFileBufChunkIter<'a, T> {
    ChunkedTmpFile { read: BufReader<Arc<File>> },
    Memory { iter: std::slice::Chunks<'a, T> },
}

impl<T> MaybeFileBuf<T> {
    /// Create an optionally temp file backed buffer.
    ///
    /// The capacity is only used for the in-memory buf if `dir` is `None`.
    pub(crate) fn new(dir: Option<&Path>, capacity: usize) -> std::io::Result<Self> {
        if let Some(dir) = dir {
            let f = Arc::new(tempfile_in(dir)?);
            let write = BufWriter::new(Arc::clone(&f));
            Ok(Self::ChunkedTmpFile { write })
        } else {
            Ok(Self::Memory {
                data: Vec::with_capacity(capacity),
            })
        }
    }

    /// Create an iterator for the [`MaybeFileBuf`].
    ///
    /// For the [`MaybeFileBuf::ChunkedTmpFile`] variant, the matching iterator
    /// will only read one of the written chunks (+ potentially the default capacity of
    /// a BufReader) and keep it in memory until it is iterated over. Then the next
    /// chunk is loaded.
    pub(crate) fn iter(&mut self) -> std::io::Result<MaybeFileBufIter<'_, T>> {
        match self {
            MaybeFileBuf::ChunkedTmpFile { write } => {
                write.flush()?;
                let mut file = Arc::clone(write.get_ref());
                file.rewind()?;
                let read = BufReader::new(file);
                Ok(MaybeFileBufIter::ChunkedTmpFile {
                    read,
                    chunk_iter: Default::default(),
                })
            }
            MaybeFileBuf::Memory { data } => Ok(MaybeFileBufIter::Memory { iter: data.iter() }),
        }
    }

    /// Iterator over the chunks stored in the file or a chunk iterator for the in-memory buf.
    ///
    /// The `chunks` parameter is only used in the [`MaybeFileBuf::Memory`] case, otherwise the
    /// exact chunks that were written to the file by [`MaybeFileBuf::write_chunk`] are returned.
    pub(crate) fn chunks(&mut self, size: usize) -> std::io::Result<MaybeFileBufChunkIter<'_, T>> {
        match self {
            MaybeFileBuf::ChunkedTmpFile { write } => {
                write.flush()?;
                let mut file = Arc::clone(write.get_ref());
                file.rewind()?;
                let read = BufReader::new(file);
                Ok(MaybeFileBufChunkIter::ChunkedTmpFile { read })
            }
            MaybeFileBuf::Memory { data } => Ok(MaybeFileBufChunkIter::Memory {
                iter: data.chunks(size),
            }),
        }
    }

    fn bincode() -> impl bincode::Options {
        bincode::options().allow_trailing_bytes()
    }
}

impl<T> Default for MaybeFileBuf<T> {
    fn default() -> Self {
        Self::Memory { data: vec![] }
    }
}

impl<T: Serialize + Clone> MaybeFileBuf<T> {
    /// Write a chunk to the temporyr file or in-memory buffer.
    pub(crate) fn write_chunk(&mut self, chunk: &[T]) -> bincode::Result<()> {
        match self {
            MaybeFileBuf::ChunkedTmpFile { write, .. } => {
                let opts = Self::bincode();
                opts.serialize_into(write, chunk)?;
            }
            MaybeFileBuf::Memory { data } => {
                data.extend_from_slice(chunk);
            }
        }
        Ok(())
    }
}

impl<'a, T: DeserializeOwned + Clone> Iterator for MaybeFileBufIter<'a, T> {
    type Item = bincode::Result<T>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            MaybeFileBufIter::ChunkedTmpFile { read, chunk_iter } => {
                if let Some(gate) = chunk_iter.next() {
                    return Some(Ok(gate));
                }
                let opts = MaybeFileBuf::<T>::bincode();
                match opts.deserialize_from::<_, Vec<T>>(read) {
                    Ok(chunk) => {
                        *chunk_iter = chunk.into_iter();
                        self.next()
                    }
                    Err(err) => {
                        if let bincode::ErrorKind::Io(io) = &*err
                            && std::io::ErrorKind::UnexpectedEof == io.kind()
                        {
                            return None;
                        }

                        Some(Err(err))
                    }
                }
            }
            MaybeFileBufIter::Memory { iter } => iter.next().map(|e| Ok(e.clone())),
        }
    }
}

// The drop impl ensures that we can create an iterator, and afterwards continue
// writing to the end of the file and overwrite existing content.
impl<'a, T> Drop for MaybeFileBufIter<'a, T> {
    fn drop(&mut self) {
        if let Self::ChunkedTmpFile { read, .. } = self {
            read.get_mut()
                .seek(SeekFrom::End(0))
                .expect("unable to reset seek position");
        }
    }
}

impl<'a, T: DeserializeOwned + Clone> Iterator for MaybeFileBufChunkIter<'a, T> {
    type Item = bincode::Result<Cow<'a, [T]>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            MaybeFileBufChunkIter::ChunkedTmpFile { read } => {
                let opts = MaybeFileBuf::<T>::bincode();
                match opts.deserialize_from::<_, Vec<T>>(read) {
                    Ok(chunk) => Some(Ok(Cow::Owned(chunk))),
                    Err(err) => {
                        if let bincode::ErrorKind::Io(io) = &*err
                            && std::io::ErrorKind::UnexpectedEof == io.kind()
                        {
                            return None;
                        }
                        Some(Err(err))
                    }
                }
            }
            MaybeFileBufChunkIter::Memory { iter } => iter.next().map(|e| Ok(Cow::Borrowed(e))),
        }
    }
}

impl<'a, T> Drop for MaybeFileBufChunkIter<'a, T> {
    fn drop(&mut self) {
        if let Self::ChunkedTmpFile { read, .. } = self {
            read.get_mut()
                .seek(SeekFrom::End(0))
                .expect("unable to reset seek position");
        }
    }
}
