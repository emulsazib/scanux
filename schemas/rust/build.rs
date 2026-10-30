//! Compiles schemas/proto with protox (pure Rust), so no protoc is needed on
//! the Mac, the Windows build VM, or CI.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_root = "../proto";
    let files = [
        "scanu/v1/envelope.proto",
        "scanu/v1/alert.proto",
        "scanu/v1/command.proto",
        "scanu/v1/hitl.proto",
        "scanu/v1/scan.proto",
        "scanu/v1/sensor_service.proto",
    ];
    let fds = protox::compile(files, [proto_root])?;
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_fds(fds)?;
    println!("cargo:rerun-if-changed={proto_root}");
    Ok(())
}
