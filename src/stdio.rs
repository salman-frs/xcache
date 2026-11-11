//! The command's stdout and stderr, forwarded as it runs and recorded as frames
//! of `[stream, length (u32 LE), bytes]`, so a hit replays them interleaved as
//! they were written.

use std::io::{self, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::thread::{self, JoinHandle};

const STDOUT: u8 = 1;
const STDERR: u8 = 2;

pub fn capture(stdout: OwnedFd, stderr: OwnedFd) -> JoinHandle<io::Result<Vec<u8>>> {
    thread::spawn(move || {
        let mut streams = [(stdout, STDOUT, true), (stderr, STDERR, true)];
        let mut frames = Vec::new();
        let mut buffer = vec![0u8; 64 * 1024];
        while streams.iter().any(|(_, _, open)| *open) {
            let mut pollfds: Vec<libc::pollfd> = streams
                .iter()
                .map(|(fd, _, open)| libc::pollfd {
                    fd: if *open { fd.as_raw_fd() } else { -1 },
                    events: libc::POLLIN,
                    revents: 0,
                })
                .collect();
            // SAFETY: pollfds is a valid array of the given length.
            if unsafe { libc::poll(pollfds.as_mut_ptr(), pollfds.len() as libc::nfds_t, -1) } < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            for (stream, pollfd) in streams.iter_mut().zip(&pollfds) {
                if pollfd.revents == 0 {
                    continue;
                }
                // SAFETY: reading into a buffer we own from a descriptor we own.
                let read = unsafe { libc::read(stream.0.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len()) };
                if read <= 0 {
                    stream.2 = false;
                    continue;
                }
                let chunk = &buffer[..read as usize];
                if stream.1 == STDOUT {
                    io::stdout().write_all(chunk).and_then(|()| io::stdout().flush())?;
                } else {
                    io::stderr().write_all(chunk)?;
                }
                push_frame(&mut frames, stream.1, chunk);
            }
        }
        Ok(frames)
    })
}

fn push_frame(frames: &mut Vec<u8>, stream: u8, chunk: &[u8]) {
    frames.push(stream);
    frames.extend_from_slice(&(chunk.len() as u32).to_le_bytes());
    frames.extend_from_slice(chunk);
}

pub fn replay(frames: &[u8]) -> io::Result<()> {
    let mut rest = frames;
    while let [stream, a, b, c, d, tail @ ..] = rest {
        let length = u32::from_le_bytes([*a, *b, *c, *d]) as usize;
        let chunk = tail.get(..length).ok_or_else(|| io::Error::other("truncated output record"))?;
        if *stream == STDOUT {
            io::stdout().write_all(chunk)?;
        } else {
            io::stderr().write_all(chunk)?;
        }
        rest = &tail[length..];
    }
    io::stdout().flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_frames_round_trip() {
        let mut frames = Vec::new();
        push_frame(&mut frames, STDOUT, b"out");
        push_frame(&mut frames, STDERR, b"err");
        assert_eq!(frames.len(), 2 * 5 + 6);
        replay(&frames).unwrap();
    }
}
