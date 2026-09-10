use zimascope_agent::{Collector, CollectorConfig};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let config = CollectorConfig::default();
    let (collector, mut batches) = match Collector::start(config).await {
        Ok(worker) => worker,
        Err(error) => {
            eprintln!("zimascope-agent: {error:#}");
            std::process::exit(1);
        }
    };

    loop {
        tokio::select! {
            batch = batches.recv() => {
                let Some(batch) = batch else { break };
                println!(
                    "sequence={} flows={} domains={} state={:?}",
                    batch.sequence,
                    batch.flows.len(),
                    batch.domains.len(),
                    batch.health.state
                );
            }
            result = tokio::signal::ctrl_c() => {
                if let Err(error) = result {
                    eprintln!("zimascope-agent: wait for shutdown signal: {error}");
                }
                break;
            }
        }
    }

    if let Err(error) = collector.shutdown().await {
        eprintln!("zimascope-agent: shutdown failed: {error:#}");
    }
}
