#[tokio::main(worker_threads = 2)]
async fn main() -> std::process::ExitCode {
    openmettle_core::run(openmettle_core::Role::Api)
        .await
        .into()
}
