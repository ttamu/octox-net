use core::any::type_name;
use core::sync::atomic::{AtomicUsize, Ordering};

const COLOR_OK: &str = "\x1b[32m";
const COLOR_FAIL: &str = "\x1b[31m";
const COLOR_RESET: &str = "\x1b[0m";

static mut CURRENT_TEST: Option<&'static str> = None;
static PASSED: AtomicUsize = AtomicUsize::new(0);
static FAILED: AtomicUsize = AtomicUsize::new(0);

pub(crate) trait Testable {
    fn run(&self);
}

impl<T: Fn()> Testable for T {
    fn run(&self) {
        let name = type_name::<T>();
        unsafe { CURRENT_TEST = Some(name) };
        self();
        PASSED.fetch_add(1, Ordering::Relaxed);
        println!("test {} ... {}ok{}", name, COLOR_OK, COLOR_RESET);
        unsafe { CURRENT_TEST = None };
    }
}

pub(crate) fn test_runner(tests: &[&dyn Testable]) -> ! {
    #[cfg(target_os = "none")]
    unsafe {
        crate::uart::init();
        crate::kalloc::init();
    };

    println!("running {} tests", tests.len());
    println!("");

    for test in tests {
        test.run();
    }

    let passed = PASSED.load(Ordering::Relaxed);
    let failed = FAILED.load(Ordering::Relaxed);
    println!(
        "\ntest result: {}ok{}, {} passed; {} failed.",
        COLOR_OK, COLOR_RESET, passed, failed
    );
    exit_qemu(QemuExitCode::Success)
}

pub(crate) fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    #[cfg(target_os = "none")]
    unsafe {
        crate::uart::init()
    };
    FAILED.fetch_add(1, Ordering::Relaxed);

    let name = unsafe { CURRENT_TEST.unwrap_or("<unknown>") };
    println!("test {} ... {}FAILED{}", name, COLOR_FAIL, COLOR_RESET);
    println!("{}", info);

    let passed = PASSED.load(Ordering::Relaxed);
    let failed = FAILED.load(Ordering::Relaxed);
    println!(
        "\ntest result: {}FAILED{}, {} passed; {} failed.",
        COLOR_FAIL, COLOR_RESET, passed, failed
    );
    exit_qemu(QemuExitCode::Fail)
}

#[repr(u32)]
enum QemuExitCode {
    Success = 0x0000_5555,
    Fail = 0x0001_3333,
}

fn exit_qemu(exit_code: QemuExitCode) -> ! {
    #[cfg(target_os = "none")]
    unsafe {
        use crate::memlayout::VIRT_TEST;
        let test_dev = VIRT_TEST as *mut u32;
        core::ptr::write_volatile(test_dev, exit_code as u32);
        loop {
            core::arch::asm!("wfi");
        }
    }

    #[cfg(not(target_os = "none"))]
    {
        let _ = exit_code;
        loop {
            core::hint::spin_loop();
        }
    }
}
