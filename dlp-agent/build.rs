fn main() {
    println!("cargo:rerun-if-changed=proto/content_analysis.proto");
    prost_build::compile_protos(&["proto/content_analysis.proto"], &["proto/"])
        .expect("protobuf compilation failed");
}
