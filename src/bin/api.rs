fn main() -> std::process::ExitCode {
    // Arguments select the offline auth-configuration check (ADR 0015); none means serve.
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    if arguments.is_empty() {
        serve()
    } else {
        openmettle_core::auth_config::check_command(&arguments).into()
    }
}

#[tokio::main(worker_threads = 2)]
async fn serve() -> std::process::ExitCode {
    openmettle_core::run(openmettle_core::Role::Api)
        .await
        .into()
}
