fn main() -> std::process::ExitCode {
    openmettle_core::run_blocking(openmettle_core::Role::Worker).into()
}
