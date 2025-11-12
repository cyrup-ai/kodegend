//! GitHub release API interaction

use anyhow::{anyhow, Result};
use serde::Deserialize;

/// GitHub release metadata from API
#[derive(Deserialize, Debug)]
pub struct GitHubRelease {
    pub tag_name: String,
    pub assets: Vec<GitHubAsset>,
}

/// GitHub release asset metadata
#[derive(Deserialize, Debug)]
pub struct GitHubAsset {
    pub name: String,
    pub browser_download_url: String,
    pub size: u64,
}

/// Fetch latest release from GitHub repository
pub async fn get_latest_release(repo: &str) -> Result<GitHubRelease> {
    let url = format!("https://api.github.com/repos/cyrup-ai/{}/releases/latest", repo);

    let client = reqwest::Client::builder()
        .user_agent("kodegen-installer/0.1")
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let response = client.get(&url).send().await?;

    if !response.status().is_success() {
        return Err(anyhow!(
            "GitHub API error for {}: HTTP {}",
            repo,
            response.status()
        ));
    }

    let release: GitHubRelease = response.json().await?;
    Ok(release)
}
