#[tokio::main(flavor = "current_thread")]
async fn main() -> std::process::ExitCode {
    openmettle_core::migrate::run().await.into()
}
