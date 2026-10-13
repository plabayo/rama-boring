//! Keeps panics in Rust code that BoringSSL calls back into from unwinding into C.
//!
//! Unwinding out of an `extern "C"` function aborts the process, so one panicking
//! callback would take down every connection. Each callback instead runs its body
//! through [`catch`] and turns a panic into that callback's native failure value;
//! where that failure surfaces as an error, the panic message travels with it.
//!
//! The path that does not panic costs nothing beyond unwind tables: every panic
//! path is cold and out of line, and no state or allocation exists until a panic.

use crate::error::ErrorStack;
use std::any::Any;
use std::panic::{catch_unwind, AssertUnwindSafe};

/// Runs `body`, returning `on_panic(message)` instead of unwinding if it panics.
#[inline(always)]
pub(crate) fn catch<R>(body: impl FnOnce() -> R, on_panic: impl FnOnce(String) -> R) -> R {
    match catch_unwind(AssertUnwindSafe(body)) {
        Ok(value) => value,
        Err(payload) => on_panic(contain(payload)),
    }
}

/// Like [`catch`], for callbacks whose `failure` makes the current operation fail:
/// the panic is reported on BoringSSL's error queue, where that failure surfaces.
#[inline(always)]
pub(crate) fn catch_reported<R>(failure: R, body: impl FnOnce() -> R) -> R {
    catch(body, |message| {
        report(message);
        failure
    })
}

/// Pushes a callback panic onto the thread's BoringSSL error queue.
#[cold]
#[inline(never)]
pub(crate) fn report(message: String) {
    ErrorStack::internal_error_string(format!("callback panicked: {message}")).put();
}

/// Returns the message of a caught panic and drops its payload, containing a
/// panic raised by the payload's own destructor.
#[cold]
#[inline(never)]
pub(crate) fn contain(payload: Box<dyn Any + Send>) -> String {
    let message = if let Some(message) = payload.downcast_ref::<&'static str>() {
        (*message).to_owned()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        String::from("non-string panic payload")
    };
    drop_payload(payload);
    message
}

/// Drops `value` where unwinding is not allowed, such as a destructor called by
/// BoringSSL; a panicking destructor is contained.
#[inline(always)]
pub(crate) fn drop_contained<T>(value: T) {
    if let Err(payload) = catch_unwind(AssertUnwindSafe(|| drop(value))) {
        drop_payload(payload);
    }
}

/// Owns a value whose destructor may panic while the stack holding it unwinds
/// from another panic, which would abort the process. On that path the value
/// is leaked instead; otherwise it drops normally.
pub(crate) struct LeakOnUnwind<T>(std::mem::ManuallyDrop<T>);

impl<T> LeakOnUnwind<T> {
    #[inline(always)]
    pub(crate) fn new(value: T) -> Self {
        Self(std::mem::ManuallyDrop::new(value))
    }
}

impl<T> std::ops::Deref for LeakOnUnwind<T> {
    type Target = T;

    #[inline(always)]
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T> Drop for LeakOnUnwind<T> {
    #[inline(always)]
    fn drop(&mut self) {
        if !std::thread::panicking() {
            // SAFETY: dropped exactly once, here.
            unsafe { std::mem::ManuallyDrop::drop(&mut self.0) }
        }
    }
}

#[cold]
#[inline(never)]
fn drop_payload(payload: Box<dyn Any + Send>) {
    if let Err(nested) = catch_unwind(AssertUnwindSafe(|| drop(payload))) {
        // Containing this one could panic again; leaking it is the safe end.
        std::mem::forget(nested);
    }
}

/// Runs a test body in a child process of the test binary. A panic escaping
/// into C aborts only that child, so a missing guard fails one test instead of
/// the whole run. A child that hangs (libtest cannot report a test whose panic
/// payload panics again) is killed and fails the test as well.
#[cfg(test)]
pub(crate) fn isolated(test: &str, body: impl FnOnce()) {
    use std::{
        io::Read,
        process::{Command, Stdio},
        thread,
        time::{Duration, Instant},
    };
    const CHILD: &str = "RAMA_BORING_ISOLATED_TEST";
    const DEADLINE: Duration = Duration::from_secs(60);
    let test = test.strip_prefix("rama_boring::").unwrap_or(test);
    if std::env::var(CHILD).is_ok_and(|name| name == test) {
        body();
        return;
    }
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([test, "--exact", "--test-threads=1"])
        .env(CHILD, test)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Drain both pipes so a chatty child cannot block on a full buffer.
    let drain = |mut pipe: Box<dyn Read + Send>| {
        thread::spawn(move || {
            let mut output = String::new();
            let _ = pipe.read_to_string(&mut output);
            output
        })
    };
    let stdout = drain(Box::new(child.stdout.take().unwrap()));
    let stderr = drain(Box::new(child.stderr.take().unwrap()));
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break Some(status);
        }
        if started.elapsed() > DEADLINE {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        thread::sleep(Duration::from_millis(5));
    };
    let (stdout, stderr) = (stdout.join().unwrap(), stderr.join().unwrap());
    assert!(
        status.is_some_and(|status| status.success())
            && stdout.contains("test result: ok. 1 passed"),
        "isolated {test}: {}\n{stdout}\n{stderr}",
        status.map_or_else(|| "timed out".to_owned(), |status| status.to_string())
    );
}

/// Declares a test that runs in its own process; see [`isolated`].
#[cfg(test)]
macro_rules! isolated_test {
    ($(#[$meta:meta])* fn $name:ident() $body:block) => {
        $(#[$meta])*
        #[test]
        fn $name() {
            $crate::unwind::isolated(concat!(module_path!(), "::", stringify!($name)), || $body);
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::panic_any;

    struct PanicOnDrop;
    impl Drop for PanicOnDrop {
        fn drop(&mut self) {
            panic!("destructor");
        }
    }

    isolated_test! {
        fn catch_returns_the_body_or_the_panic_message() {
            assert_eq!(catch(|| 7, |_| 0), 7);
            assert_eq!(catch(|| panic!("static"), |message| message), "static");
            assert_eq!(
                catch(|| panic!("formatted {}", 7), |message| message),
                "formatted 7"
            );
            assert_eq!(
                catch(|| panic_any(7u8), |message| message),
                "non-string panic payload"
            );
        }
    }

    isolated_test! {
    fn panicking_payload_and_destructors_are_contained() {
        assert_eq!(
            catch(|| panic_any(PanicOnDrop), |message| message),
            "non-string panic payload"
        );
        drop_contained(PanicOnDrop);
        drop_contained(Box::new(PanicOnDrop));
    }
    }

    isolated_test! {
        fn reported_panics_reach_the_error_queue() {
            ErrorStack::clear();
            assert_eq!(catch_reported(-1, || panic!("policy")), -1);
            let errors = ErrorStack::get();
            assert_eq!(errors.errors().len(), 1);
            assert!(
                errors.to_string().contains("callback panicked: policy"),
                "{errors}"
            );
            assert_eq!(catch_reported(-1, || 1), 1);
            assert!(ErrorStack::get().errors().is_empty());
        }
    }
}
