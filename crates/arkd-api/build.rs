fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_root = "../../proto";

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(
            &[
                "ark/v1/ark_service.proto",
                "ark/v1/admin_service.proto",
                "ark/v1/signer_service.proto",
                "ark/v1/wallet_service.proto",
            ],
            &[proto_root],
        )?;

    Ok(())
}
