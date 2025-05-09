//! Minimal run‑time metrics sink.
//!
//! Prometheus export is intentionally left out; instead we allow the host
//! process to register a raw callback that receives name/value pairs.

use metrics::{
    Counter, Gauge, Histogram, Key, KeyName, Recorder, SharedString, Unit,
};
use std::sync::Arc;
use once_cell::sync::OnceCell;
use std::os::raw::{c_char, c_ulonglong};

/// Signature for external collectors.
pub type StatsCallback = unsafe extern "C" fn(name: *const c_char, value: c_ulonglong);

static CALLBACK: OnceCell<StatsCallback> = OnceCell::new();

/// Register a callback from C/other languages.
#[no_mangle]
pub unsafe extern "C" fn cidrscan_register_stats_callback(cb: StatsCallback) {
    let _ = CALLBACK.set(cb);
}

/// Forwarding recorder. Uses the callback **if** it was registered.
struct FfiRecorder;

#[derive(Clone)]
struct FfiCounter {
    key: Key,
}
#[derive(Clone)]
struct FfiGauge {
    key: Key,
}
#[derive(Clone)]
struct FfiHistogram {
    key: Key,
}

impl Recorder for FfiRecorder {
    fn describe_counter(
        &self,
        _key: KeyName,
        _unit: Option<Unit>,
        _description: SharedString,
    ) {
        // No-op for FFI
    }
    fn describe_gauge(
        &self,
        _key: KeyName,
        _unit: Option<Unit>,
        _description: SharedString,
    ) {
        // No-op for FFI
    }
    fn describe_histogram(
        &self,
        _key: KeyName,
        _unit: Option<Unit>,
        _description: SharedString,
    ) {
        // No-op for FFI
    }

    fn register_counter(&self, key: &Key, _metadata: &metrics::Metadata<'_>) -> Counter {
        let ffi_counter = FfiCounter { key: key.clone() };
        Counter::from_arc(Arc::new(ffi_counter))
    }
    fn register_gauge(&self, key: &Key, _metadata: &metrics::Metadata<'_>) -> Gauge {
        let ffi_gauge = FfiGauge { key: key.clone() };
        Gauge::from_arc(Arc::new(ffi_gauge))
    }
    fn register_histogram(&self, key: &Key, _metadata: &metrics::Metadata<'_>) -> Histogram {
        let ffi_hist = FfiHistogram { key: key.clone() };
        Histogram::from_arc(Arc::new(ffi_hist))
    }
}

impl metrics::CounterFn for FfiCounter {
    fn increment(&self, value: u64) {
        if let Some(cb) = CALLBACK.get() {
            let name = self.key.name().as_ptr();
            unsafe { cb(name as *const c_char, value as c_ulonglong) };
        }
    }
    fn absolute(&self, value: u64) {
        if let Some(cb) = CALLBACK.get() {
            let name = self.key.name().as_ptr();
            unsafe { cb(name as *const c_char, value as c_ulonglong) };
        }
    }
}
impl metrics::GaugeFn for FfiGauge {
    fn set(&self, value: f64) {
        if let Some(cb) = CALLBACK.get() {
            let name = self.key.name().as_ptr();
            unsafe { cb(name as *const c_char, value as c_ulonglong) };
        }
    }
    fn increment(&self, value: f64) {
        if let Some(cb) = CALLBACK.get() {
            let name = self.key.name().as_ptr();
            unsafe { cb(name as *const c_char, value as c_ulonglong) };
        }
    }
    fn decrement(&self, value: f64) {
        if let Some(cb) = CALLBACK.get() {
            let name = self.key.name().as_ptr();
            unsafe { cb(name as *const c_char, value as c_ulonglong) };
        }
    }
}
impl metrics::HistogramFn for FfiHistogram {
    fn record(&self, value: f64) {
        if let Some(cb) = CALLBACK.get() {
            let name = self.key.name().as_ptr();
            unsafe { cb(name as *const c_char, value as c_ulonglong) };
        }
    }
}

/// Install exactly **once** – called from crate root.
pub fn init() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let _ = metrics::set_global_recorder(FfiRecorder);
    });
}