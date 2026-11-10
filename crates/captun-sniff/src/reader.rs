/// Big-endian cursor whose reads return `None` instead of panicking when the
/// input runs out.
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    pub(crate) fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let out = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(out)
    }

    pub(crate) fn u8(&mut self) -> Option<u8> {
        self.bytes(1).map(|b| b[0])
    }

    pub(crate) fn u16(&mut self) -> Option<u16> {
        self.bytes(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }

    /// A vector prefixed by a one-byte length.
    pub(crate) fn vec8(&mut self) -> Option<&'a [u8]> {
        let len = self.u8()?;
        self.bytes(usize::from(len))
    }

    /// A vector prefixed by a two-byte length.
    pub(crate) fn vec16(&mut self) -> Option<&'a [u8]> {
        let len = self.u16()?;
        self.bytes(usize::from(len))
    }
}
