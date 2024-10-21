

#[macro_export]
macro_rules! println_green{
    ($($arg:tt)*) => {
        println!("\x1b[32m{}\x1b[0m", format!($($arg)*));
    }
}

#[macro_export]
macro_rules! println_red{
    ($($arg:tt)*) => {
        println!("\x1b[31m{}\x1b[0m", format!($($arg)*));
    }
}