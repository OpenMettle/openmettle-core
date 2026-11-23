//! Lines and events are bounded before growth. UTF-8 is validated after a complete line. The
//! worker decoder and the gateway proxy's usage reader share this framing.
use super::Error;

const LINE: usize = 128 * 1024;
const EVENT: usize = 256 * 1024;
pub(crate) struct Event {
    pub name: Option<String>,
    pub data: Vec<u8>,
}
#[derive(Default)]
pub(crate) struct Sse {
    line: Vec<u8>,
    data: Vec<u8>,
    name: Option<String>,
    bytes: usize,
    after_cr: bool,
}
impl Sse {
    pub fn byte(&mut self, b: u8) -> Result<Option<Event>, Error> {
        if std::mem::take(&mut self.after_cr) && b == b'\n' {
            return Ok(None);
        }
        if !matches!(b, b'\r' | b'\n') {
            if self.line.len() == LINE || self.bytes == EVENT {
                return Err(Error::Malformed);
            }
            self.bytes += 1;
            self.line.push(b);
            return Ok(None);
        }
        self.after_cr = b == b'\r';
        let s = std::str::from_utf8(&self.line).map_err(|_| Error::Malformed)?;
        if s.is_empty() {
            self.bytes = 0;
            let name = self.name.take();
            if self.data.pop().is_some() {
                return Ok(Some(Event {
                    name,
                    data: std::mem::take(&mut self.data),
                }));
            }
        } else {
            let (field, value) = s.split_once(':').unwrap_or((s, ""));
            let value = value.strip_prefix(' ').unwrap_or(value);
            match field {
                "data" => {
                    if value.len() + 1 > EVENT - self.data.len() {
                        return Err(Error::Malformed);
                    }
                    self.data.extend_from_slice(value.as_bytes());
                    self.data.push(b'\n');
                }
                "event" => self.name = Some(value.into()),
                _ => {}
            }
        }
        self.line.clear();
        Ok(None)
    }
    pub fn ended(&self) -> bool {
        self.data.is_empty() && self.line.is_empty() && self.name.is_none()
    }
}
