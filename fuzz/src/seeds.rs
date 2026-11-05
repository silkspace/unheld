//! Build the world if it is not there, then copy one real object of each kind into the corpus
//! directory given as the argument.
#![forbid(unsafe_code)]

fn main() {
    let root = std::env::args().nth(1).expect("corpus directory");
    unheld_fuzz::ensure_world(&unheld_fuzz::world_dir());
    let files: [(&str, &str); 8] = [
        ("relay_wire", "message"),
        ("open", "welcome"),
        ("open", "message"),
        ("blob_text", "message"),
        ("import", "intro"),
        ("enrolment", "enrolment"),
        ("attach", "attach"),
        ("shares", "shares"),
    ];
    for (target, name) in files {
        let dir = std::path::Path::new(&root).join(target);
        std::fs::create_dir_all(&dir).expect("corpus dir");
        let bytes = unheld_fuzz::seed(name);
        let bytes = match target {
            "blob_text" => unheld_blob::Blob::from_bytes(bytes).expect("blob").to_text().into_bytes(),
            "relay_wire" => unheld_relay::wire::Request::Put { id: [1; 32], write: [2; 32], blob: unheld_blob::Blob::from_bytes(bytes).expect("blob") }.encode(),
            _ => bytes,
        };
        std::fs::write(dir.join(name), bytes).expect("seed");
    }
}
