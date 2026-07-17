
#[cfg(all(test, feature = "dangerous-real-vt-smoke"))]
mod dangerous_real_vt_smoke {
    use super::*;

    #[test]
    #[ignore = "may open and disallocate a real VT; run only on a disposable test machine"]
    fn explicitly_enabled_real_vt_allocation_smoke() {
        assert_eq!(
            std::env::var("NIRALIS_ALLOW_REAL_VT_TEST").as_deref(),
            Ok("1"),
            "set NIRALIS_ALLOW_REAL_VT_TEST=1 explicitly"
        );
        let active = std::fs::read_to_string("/sys/class/tty/tty0/active")
            .expect("the active VT should be readable before the smoke");
        let seat = SeatId::new("seat0".to_owned()).unwrap();
        let mut lease = LinuxVirtualTerminalAllocator
            .allocate(&seat)
            .expect("real VT allocation should succeed in the dedicated environment");
        let active_number = active
            .strip_prefix("tty")
            .and_then(|value| value.trim().parse::<u32>().ok())
            .expect("the active VT should have the tty<number> format");
        assert_ne!(lease.vtnr().number(), active_number);
        lease
            .activate(Duration::from_secs(1))
            .expect("the allocated VT should become active");
        assert_eq!(
            std::fs::read_to_string("/sys/class/tty/tty0/active")
                .expect("the active VT should remain readable")
                .trim(),
            format!("tty{}", lease.vtnr().number())
        );
        lease
            .release()
            .expect("owned VT should be released by the smoke");
        assert_eq!(
            std::fs::read_to_string("/sys/class/tty/tty0/active")
                .expect("the restored VT should be readable")
                .trim(),
            format!("tty{active_number}")
        );
    }
}
