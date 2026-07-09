fn main() {
    let oversized = "x".repeat((64 * 1024) + 1);
    println!("{oversized}");
}
