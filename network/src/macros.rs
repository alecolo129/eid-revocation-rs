#[macro_export]
macro_rules! log_with_time {
    ($($arg:tt)*) => {{
        println!("\x1b[32m[{}]\x1b[0m \x1b[36m{}\x1b[0m",
        $crate::chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string(),
        format!($($arg)*));
    }};
}

#[macro_export]
macro_rules! log_with_time_ln {
    ($($arg:tt)*) => {{
        println!("\x1b[32m[{}]\x1b[0m \x1b[36m{}\x1b[0m\n",
        $crate::chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string(),
        format!($($arg)*));
    }};
}
