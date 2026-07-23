#[test]
fn quadruples() {
    assert_eq!(wscore::double(wscore::double(1)), 4);
}
