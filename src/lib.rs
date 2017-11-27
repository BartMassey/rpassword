// Copyright 2014-2017 The Rpassword Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#[cfg(unix)]
extern crate libc;

#[cfg(all(unix,test))]
#[macro_use]
extern crate ptyknot;

use std::io::Write;
use std::io::Error as IoError;
use std::io::ErrorKind as IoErrorKind;

/// Sets all bytes of a String to 0
fn zero_memory(s: &mut String) {
    let vec = unsafe { s.as_mut_vec() };
    for el in vec.iter_mut() {
        *el = 0u8;
    }
}

/// Removes the \n from the read line
fn fixes_newline(mut password: String) -> std::io::Result<String> {
    // We should have a newline at the end. This helps prevent things such as:
    // > printf "no-newline" | rpassword
    // If we didn't have the \n check, we'd be removing the last "e" by mistake.
    if password.chars().last() != Some('\n') {
        return Err(IoError::new(
            IoErrorKind::UnexpectedEof,
            "unexpected end of file",
        ));
    }

    // Remove the \n from the line.
    password.pop();

    // Remove the \r from the line if present
    if password.chars().last() == Some('\r') {
        password.pop();
    }

    Ok(password)
}

/// Places a password can be read from.
pub enum PWSource {
    /// Standard input. Will check if tty.
    PWSourceStdin,
    /// Some cursor. Not a tty.
    PWSourceString(String),
    /// Some file. Will check if tty.
    PWSourceFile(std::fs::File)
}
use PWSource::*;

/// Reads a password from STDIN
pub fn read_password() -> ::std::io::Result<String> {
    read_password_with_reader(PWSourceStdin)
}

#[cfg(unix)]
mod unix {
    use libc::{c_int, isatty, tcgetattr, tcsetattr, TCSANOW, ECHO, ECHONL, STDIN_FILENO, EINVAL};
    use std;
    use std::io::{Write, BufRead, BufReader, Cursor};
    use std::fs::OpenOptions;
    use std::os::unix::io::{RawFd, AsRawFd};
    use super::PWSource;
    use super::PWSource::*;
    use super::IoError;

    /// Turns a C function return into an IO Result
    fn io_result(ret: c_int) -> ::std::io::Result<()> {
        match ret {
            0 => Ok(()),
            _ => Err(::std::io::Error::last_os_error()),
        }
    }

    /// Rust wrapper for isatty().
    fn is_tty(fd: RawFd) -> ::std::io::Result<Option<RawFd>> {
        match unsafe { isatty(fd) } {
            1 => Ok(Some(fd)),
            0 => {
                let e = IoError::last_os_error();
                if let Some(c) = e.raw_os_error() {
                    if c == EINVAL as i32 {
                        return Ok(None)
                    }
                };
                Err(e)
            },
            _ => panic!("unexpected isatty() return")
        }
    }

    /// Reads a password from anything that implements BufRead.
    pub fn read_password_with_reader(source: PWSource) -> ::std::io::Result<String> {
        let mut password = String::new();

        let mut buf_reader: Box<BufRead> = match source {
            PWSourceStdin => Box::new(BufReader::new(::std::io::stdin())),
            PWSourceString(ref string) => Box::new(Cursor::new(string.as_bytes().clone())),
            PWSourceFile(ref file) => Box::new(BufReader::new(file)),
        };

        let tty_fd = match source {
            PWSourceStdin => is_tty(STDIN_FILENO)?,
            PWSourceString(_) => None,
            PWSourceFile(ref file) => is_tty(file.as_raw_fd())?
        };

        // When we ask for a password in a terminal, we'll
        // want to hide the password as it is typed by the
        // user
        if let Some(source_fd) = tty_fd {
            // Make two copies of the terminal settings. The
            // first one will be modified and the second one
            // will act as a backup for when we want to set
            // the terminal back to its original state.
            let mut term = unsafe { ::std::mem::uninitialized() };
            let mut term_orig = unsafe { ::std::mem::uninitialized() };
            io_result(unsafe { tcgetattr(source_fd, &mut term) })?;
            io_result(unsafe { tcgetattr(source_fd, &mut term_orig) })?;


            // Hide the password. This is what makes this function useful.
            term.c_lflag &= !ECHO;

            // But don't hide the NL character when the user hits ENTER.
            term.c_lflag |= ECHONL;

            // Save the settings for now.
            io_result(unsafe { tcsetattr(source_fd, TCSANOW, &term) })?;

            // Read the password.
            let input = buf_reader.read_line(&mut password);

            // Reset the terminal.
            match io_result(unsafe { tcsetattr(source_fd, TCSANOW, &term_orig) }) {
                Ok(_) => {}
                Err(err) => {
                    super::zero_memory(&mut password);
                    return Err(err);
                }
            };

            match input {
                Ok(_) => {}
                Err(err) => {
                    super::zero_memory(&mut password);
                    return Err(err);
                }
            }

        } else {
            // If we don't have a TTY, the input was piped so we bypass
            // terminal hiding code
            match buf_reader.read_line(&mut password) {
                Ok(_) => {}
                Err(err) => {
                    super::zero_memory(&mut password);
                    return Err(err);
                }
            }
        }

        // XXX Hold the tty open until done with it.
        drop(tty_fd);

        super::fixes_newline(password)
    }

    /// (UNIX only) Prompts for a password on /dev/tty and
    /// reads it from /dev/tty
    pub fn prompt_password_tty(prompt: &str)
                               -> std::io::Result<String> {
        let mut tty =
            OpenOptions::new().read(true).write(true).open("/dev/tty")?;

        write!(tty, "{}", prompt)?;
        tty.flush()?;

        read_password_with_reader(PWSourceFile(tty))
    }
}

#[cfg(windows)]
mod windows {
    extern crate winapi;
    extern crate kernel32;

    /// Reads a password from anything that implements BufRead
    pub fn read_password_with_reader(source: PWSource) -> ::std::io::Result<String> {
        let mut password = String::new();

        // Get the stdin handle
        let handle = unsafe { kernel32::GetStdHandle(winapi::STD_INPUT_HANDLE) };
        if handle == winapi::INVALID_HANDLE_VALUE {
            return Err(::std::io::Error::last_os_error());
        }

        // Get the old mode so we can reset back to it when we are done
        let mut mode = 0;
        if unsafe { kernel32::GetConsoleMode(handle, &mut mode as winapi::LPDWORD) } == 0 {
            return Err(::std::io::Error::last_os_error());
        }

        // We want to be able to read line by line, and we still want backspace to work
        let new_mode_flags = winapi::ENABLE_LINE_INPUT | winapi::ENABLE_PROCESSED_INPUT;
        if unsafe { kernel32::SetConsoleMode(handle, new_mode_flags) } == 0 {
            return Err(::std::io::Error::last_os_error());
        }

        // Read the password.
        let input = match source {
            PWSourceStdin => ::std::io::stdin().read_line(&mut password),
            PWSourceString(string) => Cursor::new(string.as_bytes()).read_line(&mut password),
            PWSourceFile(_) =>
                return ::std::io::Err(::std::io::ErrorKind::InvalidData,
                                      "reading password from file not supported in windows")
        };

        // Check the response.
        match input {
            Ok(_) => {}
            Err(err) => {
                super::zero_memory(&mut password);
                return Err(err);
            }
        };

        // Set the the mode back to normal
        if unsafe { kernel32::SetConsoleMode(handle, mode) } == 0 {
            return Err(::std::io::Error::last_os_error());
        }

        // Since the newline isn't echo'd we need to do it ourselves
        println!("");

        super::fixes_newline(password)
    }
}

#[cfg(unix)]
pub use unix::read_password_with_reader;
#[cfg(unix)]
pub use unix::prompt_password_tty;
#[cfg(windows)]
pub use windows::read_password_with_reader;

/// Prompts for a password on STDOUT and reads it from STDIN
pub fn prompt_password_stdout(prompt: &str) -> std::io::Result<String> {
    let mut stdout = std::io::stdout();

    write!(stdout, "{}", prompt)?;
    stdout.flush()?;
    read_password()
}

/// Prompts for a password on STDERR and reads it from STDIN
pub fn prompt_password_stderr(prompt: &str) -> std::io::Result<String> {
    let mut stderr = std::io::stderr();

    write!(stderr, "{}", prompt)?;
    stderr.flush()?;
    read_password()
}

#[cfg(test)]
mod tests_all {
    use super::PWSource::*;

    #[test]
    fn can_read_from_redirected_input() {
        let mock_input_crlf = "A mocked response.\r\n".to_string();
        let mock_input_lf = "A mocked response.\n".to_string();

        let response = ::read_password_with_reader(PWSourceString(mock_input_crlf)).expect("failed to read password with crlf");
        assert_eq!(response, "A mocked response.");
        let response = ::read_password_with_reader(PWSourceString(mock_input_lf)).expect("failed to read password with lf");;
        assert_eq!(response, "A mocked response.");
    }
}

#[cfg(all(unix,test))]
mod tests_unix {
    use std::io::{Write, Read, BufRead, BufReader, BufWriter};
    use std::fs::File;
    use std::os::unix::io::FromRawFd;

    #[test]
    fn can_use_tty() {
        const PROMPT: &str = "? ";
        const RESPONSE: &str = "secret";

        fn slave() {
            let pw = ::prompt_password_tty(PROMPT)
                .expect("cannot get password from /dev/tty");
            let outfile = unsafe{File::from_raw_fd(6)};
            let mut outbuf = BufWriter::new(outfile);
            writeln!(outbuf, "{}", pw)
                .expect("cannot write secret to fd");
            outbuf.flush().expect("cannot flush secret fd");
        }

        // XXX Have to read from weird fd because test
        // runner is super-aggressive about grabbing
        // stdout/stderr.
        ptyknot!(knot, slave, @ pty, < slave_stderr 6);

        // Get the prompt.
        let mut received_prompt = PROMPT.as_bytes().to_vec();
        let nread = pty.read(&mut received_prompt)
                       .expect("cannot read prompt from pty");
        assert!(nread == PROMPT.len());
        assert!(received_prompt == PROMPT.as_bytes());

        // Send the response.
        let mut sent_response = RESPONSE.as_bytes().to_vec();
        sent_response.push(b'\n');
        pty.write(&sent_response).expect("cannot write pty");
        pty.flush().expect("cannot flush pty");

        // Get the secret.
        let mut read_response = String::new();
        BufReader::new(slave_stderr)
            .read_line(&mut read_response).expect("cannot read secret");
        let expected_response = format!("{}\n", RESPONSE);
        assert!(read_response == expected_response);

        // Get the newline.
        let mut received_nl = vec![b'\n'];
        let nread = pty.read(&mut received_nl.as_mut_slice())
                       .expect("cannot read nl from pty");
        assert!(nread == 1);
        assert!(received_nl[0] == b'\r');

        // This will wait for the child.
        drop(knot);
    }
}
