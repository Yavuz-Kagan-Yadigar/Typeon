//! Core lock: the one `P2PCore` mutex, its guards and the stall watcher.

use super::*;


/// Poll dışındaki kaç çağıran şu an çekirdek kilidini bekliyor.
pub(crate) static LOCK_WANTED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
/// Poll dışı bir çağıran kilidi bıraktı: swarm'a iş kuyruklanmış olabilir
/// (ör. gönderilen mesaj) — bekleyen poll hemen dönüp tele çıkarsın.
pub(crate) static CORE_DIRTY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// A `catch_panic` caught a panic; `poll_events` reports it once.
pub(crate) static CORE_PANICKED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Her JNI export'u `CORE.lock()` alır — bunu DOĞRUDAN `.unwrap()` etmek
/// (önceki hâli) ciddi bir kırılganlık taşıyordu: `std::sync::Mutex`,
/// kilit TUTULURKEN bir panik olursa kalıcı olarak "poisoned" (zehirli)
/// hâle gelir; `catch_panic` (bkz. dosya sonu, JNI Bindings bölümü) TEK
/// bir JNI çağrısını izbadılasa da, kilidin kendisi zehirlendiğinde
/// SONRAKİ HER `core_lock()` çağrısı (yani gerçekte HER JNI
/// export'u — pollNetwork dahil) ANINDA panikler. Sonuç: TEK bir yerde
/// (ör. bu oturumda eklenen geniş yeni kod yüzeyinden herhangi biri)
/// oluşan TEK bir panik, süreç yeniden başlatılana kadar UYGULAMANIN TÜM
/// ağ/mesajlaşma işlevselliğini SESSİZCE (kullanıcıya hiçbir hata
/// göstermeden — pollNetwork boş sonuç döner, "her şey normal görünür
/// ama hiçbir şey ASLA ilerlemez") kalıcı olarak durdurabilirdi. Bu,
/// "indirme 0B'de sonsuza kadar takılı kalıyor, hiç hata görünmüyor"
/// gibi tam olarak bu türden bir arızayla eşleşen bir belirti üretir.
/// `unwrap_or_else(|poisoned| poisoned.into_inner())` ile zehirlenmeyi
/// YOKSAYIP alttaki veriyi olduğu gibi geri alıyoruz — `catch_panic`
/// zaten her çağrıyı izbadıladığı için, TEK bir başarısız işlemin
/// yarım kalmış bir durum bırakma riski (kabul edilebilir, nadir bir
/// tutarsızlık) her şeyin kalıcı olarak kilitlenmesinden çok daha iyi.
#[track_caller]
pub(crate) fn core_lock() -> CoreGuard {
    use std::sync::atomic::Ordering;
    LOCK_WANTED.fetch_add(1, Ordering::SeqCst);
    NET_WAKE.notify_waiters();
    let guard = CORE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    LOCK_WANTED.fetch_sub(1, Ordering::SeqCst);
    lock_watch::acquired(std::panic::Location::caller());
    CoreGuard(Some(guard))
}

/// For read-only status queries (the chat screen asks every few seconds). It
/// has to end the idle wait to get the lock, but leaves `CORE_DIRTY` alone,
/// so the poll loop does not run a second turn for a caller that changed nothing.
#[track_caller]
pub(crate) fn core_lock_read() -> ReadGuard {
    use std::sync::atomic::Ordering;
    LOCK_WANTED.fetch_add(1, Ordering::SeqCst);
    NET_WAKE.notify_waiters();
    let guard = CORE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    LOCK_WANTED.fetch_sub(1, Ordering::SeqCst);
    lock_watch::acquired(std::panic::Location::caller());
    ReadGuard(PollGuard(guard))
}

/// `core_lock_read` return value: shared access only, so a caller cannot
/// change state without `CORE_DIRTY` being set.
pub(crate) struct ReadGuard(PollGuard);
impl std::ops::Deref for ReadGuard {
    type Target = P2PCore;
    fn deref(&self) -> &P2PCore { &self.0 }
}

/// Poll döngüsünün kendi kilidi — `CORE_DIRTY`'yi işaretlemez, yoksa her
/// poll turu bir sonrakini hemen uyandırırdı.
#[track_caller]
pub(crate) fn core_lock_poll() -> PollGuard {
    let guard = CORE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    lock_watch::acquired(std::panic::Location::caller());
    PollGuard(guard)
}

/// `core_lock_poll` return value; releasing it clears the watchdog record.
pub(crate) struct PollGuard(std::sync::MutexGuard<'static, P2PCore>);
impl std::ops::Deref for PollGuard {
    type Target = P2PCore;
    fn deref(&self) -> &P2PCore { &self.0 }
}
impl std::ops::DerefMut for PollGuard {
    fn deref_mut(&mut self) -> &mut P2PCore { &mut self.0 }
}
impl Drop for PollGuard {
    fn drop(&mut self) {
        lock_watch::released();
    }
}

/// Diagnostics for a stalled core. Found on device (2026-09-18): the Note 9S
/// core stopped for 4 minutes (no log line, no keepalive answer) with no crash,
/// and a release build gives no way to get a stack. A watchdog thread logs who
/// holds the core lock (caller file:line) and which `poll_events` phase is
/// running once the lock is held past `STALL_LOG_AFTER_MS`.
pub(crate) mod lock_watch {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;
    const STALL_LOG_AFTER_MS: u64 = 10_000;
    static HELD_SINCE: AtomicU64 = AtomicU64::new(0);
    static HOLDER: Mutex<Option<&'static std::panic::Location<'static>>> = Mutex::new(None);
    static PHASE: Mutex<&'static str> = Mutex::new("-");
    static STARTED: std::sync::Once = std::sync::Once::new();
    static WATCHER: std::sync::OnceLock<std::thread::Thread> = std::sync::OnceLock::new();

    pub(crate) fn acquired(at: &'static std::panic::Location<'static>) {
        if let Ok(mut h) = HOLDER.lock() { *h = Some(at); }
        HELD_SINCE.store(crate::current_time_ms(), Ordering::SeqCst);
        STARTED.call_once(|| {
            // One line per doubling of the stall (10 s, 20 s, 40 s ...), not
            // one every 5 s for the whole stall. H72: the thread sleeps until
            // the next log is due and parks while nobody holds the lock (it
            // woke every 5 s for the life of the process).
            if let Ok(h) = std::thread::Builder::new().name("core-lock-watch".into()).spawn(|| {
                let (mut stall_since, mut next_log_ms) = (0u64, 0u64);
                loop {
                    let since = HELD_SINCE.load(Ordering::SeqCst);
                    if since == 0 {
                        std::thread::park();
                        continue;
                    }
                    if since != stall_since {
                        stall_since = since;
                        next_log_ms = STALL_LOG_AFTER_MS;
                    }
                    let held = crate::current_time_ms().saturating_sub(since);
                    // The idle wait holds the lock by design, but for at most 30 s.
                    let idle_wait = PHASE.lock().map(|p| *p == "wait_network").unwrap_or(false);
                    let due = if idle_wait { next_log_ms.max(60_000) } else { next_log_ms };
                    if held >= due {
                        next_log_ms = held.saturating_mul(2);
                        let holder = HOLDER.lock().ok().and_then(|h| *h).map(|l| format!("{}:{}", l.file(), l.line())).unwrap_or_default();
                        let phase = PHASE.lock().map(|p| *p).unwrap_or("?");
                        log::warn!("Çekirdek kilidi {} sn'dir tutuluyor: alan={} poll_fazı={}", held / 1000, holder, phase);
                        continue;
                    }
                    // Woken early by `acquired` (new holder) or after the wait.
                    std::thread::park_timeout(std::time::Duration::from_millis((due - held).max(1_000)));
                }
            }) {
                let _ = WATCHER.set(h.thread().clone());
            }
        });
        if let Some(t) = WATCHER.get() { t.unpark(); }
    }
    pub(crate) fn released() {
        HELD_SINCE.store(0, Ordering::SeqCst);
        if let Ok(mut p) = PHASE.lock() { *p = "-"; }
    }
    pub(crate) fn phase(name: &'static str) {
        if let Ok(mut p) = PHASE.lock() { *p = name; }
    }
}

/// `core_lock` dönüşü: bırakılınca bekleyen poll'u uyandırır.
pub(crate) struct CoreGuard(Option<std::sync::MutexGuard<'static, P2PCore>>);
impl std::ops::Deref for CoreGuard {
    type Target = P2PCore;
    fn deref(&self) -> &P2PCore { self.0.as_ref().unwrap() }
}
impl std::ops::DerefMut for CoreGuard {
    fn deref_mut(&mut self) -> &mut P2PCore { self.0.as_mut().unwrap() }
}
impl Drop for CoreGuard {
    fn drop(&mut self) {
        lock_watch::released();
        self.0.take();
        CORE_DIRTY.store(true, std::sync::atomic::Ordering::SeqCst);
        NET_WAKE.notify_waiters();
    }
}

/// Poll döngüsü saniyede bir uyanmak yerine bunu çağırır: swarm'da bir olay
/// olana (gelen bayt, yeni bağlantı, zamanlayıcı), başka bir çağıran çekirdeği
/// isteyene/bırakana ya da `timeout_ms` dolana kadar bekler. Önceden ağ yığını
/// YALNIZCA `poll_events` çağrıldığında ilerliyordu: giden mesaj bir sonraki
/// tura kadar tele çıkmıyor, gelen de işlenmiyordu — cihazda Tor üzerinden
/// mesaj başına ~1-2 sn fazladan gecikme ölçüldü.
pub(crate) fn wait_for_network_activity(timeout_ms: u64) {
    use std::sync::atomic::Ordering;
    let notified = NET_WAKE.notified();
    tokio::pin!(notified);
    notified.as_mut().enable();
    let mut core = core_lock_poll();
    lock_watch::phase("wait_network"); // holding the lock while idle-waiting is by design
    if LOCK_WANTED.load(Ordering::SeqCst) > 0 || CORE_DIRTY.swap(false, Ordering::SeqCst) {
        return;
    }
    if !core.attachment_events.is_empty() || !core.deferred_swarm_events.is_empty() {
        return;
    }
    // clamped; Long.MAX_VALUE panicked in `tokio::time::sleep` (Instant overflow).
    let timeout_ms = timeout_ms.min(60_000);
    let timeout = std::time::Duration::from_millis(timeout_ms);
    let started = std::time::Instant::now();
    let event = match core.swarm.as_mut() {
        Some(swarm) => RUNTIME.block_on(async {
            tokio::select! {
                ev = swarm.next() => ev,
                _ = notified => None,
                _ = tokio::time::sleep(timeout) => None,
            }
        }),
        None => {
            drop(core);
            RUNTIME.block_on(async {
                tokio::select! {
                    _ = notified => {},
                    _ = tokio::time::sleep(timeout) => {},
                }
            });
            return;
        }
    };
    let waited = started.elapsed().as_millis() as u64;
    if waited > timeout_ms + 5_000 {
        log::warn!("Ağ beklemesi zaman aşımını aştı: {} ms (zaman aşımı {} ms)", waited, timeout_ms);
    }
    if let Some(ev) = event {
        core.deferred_swarm_events.push(ev);
    }
}
