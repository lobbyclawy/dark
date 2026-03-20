fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_root = "../../proto";

    tonic_build::configure()
        .build_server(true)
        .build_client(false)
        .compile_protos(&["ark/v1/wallet_service.proto"], &[proto_root])?;

    Ok(())
}
