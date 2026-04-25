fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_root = "../../proto";

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .file_descriptor_set_path(
            std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("ark_descriptor.bin"),
        )
        .compile_protos(
            &[
                "ark/v1/ark_service.proto",
                "ark/v1/admin_service.proto",
                "ark/v1/confidential.proto",
                "ark/v1/confidential_tx.proto",
                "ark/v1/indexer_service.proto",
                "ark/v1/signer_service.proto",
                "ark/v1/signer_manager_service.proto",
                "ark/v1/wallet_service.proto",
            ],
            &[proto_root],
        )?;

    Ok(())
}
