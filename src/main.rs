#[tokio::main]
async fn main() {
    let exit_status = horizon::run().await;

    println!("{exit_status:#?}");
}
