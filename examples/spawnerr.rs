use anyhow::anyhow;
use futures::future::pending;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let h1 = tokio::spawn(async { Err::<(), _>(anyhow!("a")) });
    let h2 = tokio::spawn(async { Err::<(), _>(anyhow!("b")) });

    let k = tokio::select!(h = h1 => h?, h = h2 => h?);
    k?;

    pending::<()>().await;
    Ok(())
}
