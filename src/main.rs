#[tokio::main]
async fn main() {
    #[cfg(feature = "tokio-console")]
    console_subscriber::init();

    let exit_status = horizon::run().await;

    println!("{exit_status:#?}");
}
