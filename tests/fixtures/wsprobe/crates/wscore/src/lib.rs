pub fn double(x: i32) -> i32 {
    x * 2
}

#[test]
fn doubles() {
    assert_eq!(double(2), 4);
}
