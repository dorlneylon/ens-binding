use alloy::{
    network::{Ethereum, EthereumWallet},
    primitives::{Address, FixedBytes, U256},
    providers::{PendingTransactionBuilder, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol,
    transports::BoxTransport,
};
use eyre::Result;
use rand::RngCore;
use std::{env, str::FromStr};
use EthRegistrarController::rentPriceReturn;

#[allow(unused)]
const ENS_REGISTRY_ADDRESS: &str = "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e";
const BASE_REGISTRAR_ADDRESS: &str = "0x253553366Da8546fC250F225fe3d25d0C782303b";
const MIN_REGISTRATION_DURATION: u64 = 365 * 24 * 60 * 60;

sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    EnsRegistry,
    "abi/ENS.json"
}

sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    EthRegistrarController,
    "abi/ETHRegistrarController.json"
}

/// Adds a record to the ENS registry
///
/// # Arguments
/// * `rpc_url` - The RPC endpoint URL
/// * `wallet` - The wallet used for the transaction
/// * `node` - The ENS node (namehash) to add the record for
/// * `owner` - The new owner of the node
/// * `resolver` - The resolver address for this node
async fn add_record(
    rpc_url: &str,
    wallet: EthereumWallet,
    node: FixedBytes<32>,
    owner: Address,
    resolver: Option<Address>,
) -> Result<()> {
    let provider = ProviderBuilder::default()
        .with_recommended_fillers()
        .wallet(wallet.clone())
        .on_builtin(rpc_url)
        .await?;

    let ens_registry = EnsRegistry::new(Address::from_str(ENS_REGISTRY_ADDRESS)?, &provider);

    let set_owner_tx: PendingTransactionBuilder<BoxTransport, Ethereum> =
        ens_registry.setOwner(node, owner).send().await?;
    let owner_tx_hash = set_owner_tx.watch().await?;
    println!("Set Owner Tx Hash: {:?}", owner_tx_hash);

    if let Some(resolver_addr) = resolver {
        let set_resolver_tx = ens_registry.setResolver(node, resolver_addr).send().await?;
        let resolver_tx_hash = set_resolver_tx.watch().await?;
        println!("Set Resolver Tx Hash: {:?}", resolver_tx_hash);
    }

    Ok(())
}

/// Registers a subname for an existing ENS domain
///
/// # Arguments
/// * `rpc_url` - The RPC endpoint URL
/// * `wallet` - The wallet used for the transaction
/// * `parent_node` - The parent domain's namehash
/// * `label` - The label for the subname (e.g., "subdomain" for subdomain.parent.eth)
/// * `owner` - The owner address for the new subname
/// * `resolver` - Optional resolver address
async fn register_subname(
    rpc_url: &str,
    wallet: EthereumWallet,
    parent_node: FixedBytes<32>,
    label: &str,
    owner: Address,
    resolver: Option<Address>,
) -> Result<()> {
    let provider = ProviderBuilder::default()
        .with_recommended_fillers()
        .wallet(wallet.clone())
        .on_builtin(rpc_url)
        .await?;

    let ens_registry = EnsRegistry::new(Address::from_str(ENS_REGISTRY_ADDRESS)?, &provider);

    let label_hash = FixedBytes::from(keccak256(label.as_bytes()));
    let subname_node = name_hash(parent_node, label_hash);

    let set_subowner_tx: PendingTransactionBuilder<BoxTransport, Ethereum> = ens_registry
        .setSubnodeOwner(parent_node, label_hash, owner)
        .send()
        .await?;

    let subowner_tx_hash = set_subowner_tx.watch().await?;
    println!("Set Subname Owner Tx Hash: {:?}", subowner_tx_hash);

    if let Some(resolver_addr) = resolver {
        let set_resolver_tx = ens_registry
            .setResolver(subname_node, resolver_addr)
            .send()
            .await?;

        let resolver_tx_hash = set_resolver_tx.watch().await?;
        println!("Set Subname Resolver Tx Hash: {:?}", resolver_tx_hash);
    }

    Ok(())
}

/// Computes the namehash for a given parent node and label
fn name_hash(parent_node: FixedBytes<32>, label_hash: FixedBytes<32>) -> FixedBytes<32> {
    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(parent_node.as_slice());
    combined[32..].copy_from_slice(label_hash.as_slice());

    FixedBytes::from(keccak256(&combined))
}

/// Computes the Keccak-256 hash of the input
fn keccak256(input: &[u8]) -> [u8; 32] {
    use sha3::{Digest, Keccak256};
    let mut hasher = Keccak256::new();
    hasher.update(input);
    hasher.finalize().into()
}

/// Registers an ENS domain name
///
/// # Arguments
/// * `rpc_url` - The RPC endpoint URL
/// * `private_key` - The private key of the wallet registering the domain
/// * `domain_name` - The domain name to register (without .eth)
/// * `owner_address` - The address that will own the domain
/// * `duration` - Registration duration in years
async fn register_ens_domain(
    rpc_url: &str,
    domain_name: &str,
    owner_address: Address,
    duration: u64,
    wallet: EthereumWallet,
) -> Result<()> {
    let provider = ProviderBuilder::default()
        .with_recommended_fillers()
        .wallet(wallet)
        .on_builtin(rpc_url)
        .await?;

    let registrar_controller =
        EthRegistrarController::new(Address::from_str(BASE_REGISTRAR_ADDRESS)?, &provider);

    let available = registrar_controller
        .available(domain_name.to_string())
        .call()
        .await?;

    if !available._0 {
        return Err(eyre::eyre!("Domain is not available"));
    }

    let duration_seconds = U256::from(duration * 365 * 24 * 60 * 60);

    let mut secret = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut secret);
    let secret_bytes = FixedBytes::from(secret);

    println!("Secret: {:?}", secret_bytes);

    let resolver = Address::ZERO;
    let data = vec![];

    let commitment = registrar_controller
        .makeCommitment(
            domain_name.to_string(),
            owner_address,
            duration_seconds,
            secret_bytes,
            resolver,
            data.clone(),
            false,
            0,
        )
        .call()
        .await?;

    let commit_tx: PendingTransactionBuilder<BoxTransport, Ethereum> =
        registrar_controller.commit(commitment._0).send().await?;
    let hash = commit_tx.watch().await;

    println!("Commitment Tx Hash: {:?}", hash);

    std::thread::sleep(std::time::Duration::from_secs(60));

    let rentPriceReturn { price } = registrar_controller
        .rentPrice(domain_name.to_string(), duration_seconds)
        .call()
        .await?;

    let register_tx = registrar_controller
        .register(
            domain_name.to_string(),
            owner_address,
            duration_seconds,
            secret_bytes,
            resolver,
            data,
            false,
            0,
        )
        .value(price.base)
        .send()
        .await?;

    println!("Domain registered successfully");
    println!("Registration Tx Hash: {:?}", register_tx.tx_hash());

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv::dotenv().expect("Failed to read `.env` file");
    let rpc_url = &env::var("RPC_URL").expect("RPC_URL must be set");
    let private_key = &env::var("PRIVATE_KEY").expect("PRIVATE_KEY must be set");
    let signer = PrivateKeySigner::from_str(private_key)?;
    let wallet = EthereumWallet::from(signer);

    register_ens_domain(
        rpc_url,
        "kyssssing",
        wallet.default_signer().address(),
        MIN_REGISTRATION_DURATION,
        wallet,
    )
    .await
    .unwrap();

    Ok(())
}
