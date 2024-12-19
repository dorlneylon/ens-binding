use anyhow::Result;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::get,
    Router,
};
use ethers::{
    abi::{Abi, Token},
    contract::Contract,
    providers::{Http, Middleware, Provider},
    types::{Address, BlockId, Bytes, H256, U128, U256, U64},
    utils::hex,
};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, str::FromStr, sync::Arc};

const L2_TO_L1_MESSAGE_PASSER: &str = "0x4200000000000000000000000000000000000016";
const OP_OUTPUT_LOOKUP: &str = "0x475dc200b71dbd9776518C299e281766FaDf4A30";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OutputProposal {
    output_root: H256,
    timestamp: U128,
    l2_block_number: U128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OPProvableBlock {
    number: u64,
    proof_type: u8,
    index: u64,
}

#[derive(Debug)]
struct AccountProof {
    storage_hash: H256,
    state_trie_witness: Vec<u8>,
    storage_proofs: Vec<Vec<u8>>,
}

#[derive(Debug, Clone)]
struct OPProofService {
    l1_provider: Arc<Provider<Http>>,
    l2_provider: Arc<Provider<Http>>,
    optimism_portal: Address,
    output_lookup: Arc<Contract<Provider<Http>>>,
    min_age: u64,
}

impl OPProofService {
    pub async fn new(
        l1_provider: Provider<Http>,
        l2_provider: Provider<Http>,
        optimism_portal: Address,
        min_age: u64,
    ) -> Result<Self> {
        let l1_provider = Arc::new(l1_provider);

        let abi: Abi = serde_json::from_str(include_str!("../abi/OPOutputLookup.json"))?;
        let output_lookup = Arc::new(Contract::new(
            Address::from_str(OP_OUTPUT_LOOKUP)?,
            abi,
            l1_provider.clone(),
        ));

        Ok(Self {
            l1_provider,
            l2_provider: Arc::new(l2_provider),
            optimism_portal,
            output_lookup,
            min_age,
        })
    }

    pub async fn get_storage_at(
        &self,
        block: &OPProvableBlock,
        address: Address,
        slot: U256,
    ) -> Result<H256> {
        let block_number = BlockId::Number(U64::from(block.number).into());
        let slot_bytes = H256::from_low_u64_be(slot.as_u64());
        let value = self
            .l2_provider
            .get_storage_at(address, slot_bytes, Some(block_number))
            .await?;
        Ok(value)
    }

    pub async fn get_proofs(
        &self,
        block: &OPProvableBlock,
        address: Address,
        slots: Vec<U256>,
    ) -> Result<String> {
        let proof = self.get_proof(block.number, address, &slots).await?;
        let rpc_block = self
            .l2_provider
            .get_block(block.number)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Block not found"))?;

        let message_passer_storage_root =
            self.get_message_passer_storage_root(block.number).await?;

        let encoded = ethers::abi::encode(&[
            Token::Tuple(vec![
                Token::Uint(block.proof_type.into()),
                Token::Uint(block.index.into()),
                Token::Tuple(vec![
                    Token::FixedBytes(vec![0; 32]),
                    Token::FixedBytes(rpc_block.state_root.as_bytes().to_vec()),
                    Token::FixedBytes(message_passer_storage_root.as_bytes().to_vec()),
                    Token::FixedBytes(rpc_block.hash.unwrap().as_bytes().to_vec()),
                ]),
            ]),
            Token::Tuple(vec![
                Token::Bytes(proof.state_trie_witness),
                Token::Array(proof.storage_proofs.into_iter().map(Token::Bytes).collect()),
            ]),
        ]);

        Ok(hex::encode(encoded))
    }

    async fn get_message_passer_storage_root(&self, block_number: u64) -> Result<H256> {
        let proof = self
            .get_proof(
                block_number,
                Address::from_str(L2_TO_L1_MESSAGE_PASSER)?,
                &[],
            )
            .await?;
        Ok(proof.storage_hash)
    }

    async fn get_proof(
        &self,
        block_number: u64,
        address: Address,
        slots: &[U256],
    ) -> Result<AccountProof> {
        let slot_hashes: Vec<H256> = slots
            .iter()
            .map(|s| H256::from_low_u64_be(s.as_u64()))
            .collect();

        let proof = self
            .l2_provider
            .get_proof(address, slot_hashes, Some(block_number.into()))
            .await?;

        Ok(AccountProof {
            storage_hash: proof.storage_hash,
            state_trie_witness: proof
                .account_proof
                .into_iter()
                .flat_map(|b| b.to_vec())
                .collect(),
            storage_proofs: proof
                .storage_proof
                .into_iter()
                .map(|p| p.proof.into_iter().flat_map(|b| b.to_vec()).collect())
                .collect(),
        })
    }
}

#[derive(Debug)]
struct EVMGateway {
    proof_service: Arc<OPProofService>,
}

impl EVMGateway {
    pub fn new(proof_service: Arc<OPProofService>) -> Self {
        Self { proof_service }
    }
}

#[derive(Clone)]
struct AppState {
    gateway: Arc<EVMGateway>,
}

#[derive(Debug, Deserialize)]
struct ProofRequest {
    block: u64,
    address: String,
    slots: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ProofResponse {
    proof: String,
}

async fn handle_proof_request(
    State(state): State<AppState>,
    Query(params): Query<ProofRequest>,
) -> Result<Json<ProofResponse>, StatusCode> {
    let address: Address = params
        .address
        .parse()
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let slots: Result<Vec<U256>, _> = params.slots.iter().map(|s| s.parse()).collect();
    let slots = slots.map_err(|_| StatusCode::BAD_REQUEST)?;

    let block = OPProvableBlock {
        number: params.block,
        proof_type: 0,
        index: 0,
    };

    let proof = state
        .gateway
        .proof_service
        .get_proofs(&block, address, slots)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(ProofResponse { proof }))
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv::dotenv().ok();

    let l1_provider_url = std::env::var("L1_PROVIDER_URL")?;
    let l2_provider_url = std::env::var("L2_PROVIDER_URL")?;
    let optimism_portal = std::env::var("OPTIMISM_PORTAL_ADDRESS")?;
    let min_age = std::env::var("MIN_AGE")?.parse::<u64>()?;

    let l1_provider = Provider::<Http>::try_from(l1_provider_url)?;
    let l2_provider = Provider::<Http>::try_from(l2_provider_url)?;
    let optimism_portal_address: Address = optimism_portal.parse()?;

    let proof_service =
        OPProofService::new(l1_provider, l2_provider, optimism_portal_address, min_age).await?;

    let gateway = EVMGateway::new(Arc::new(proof_service));

    let state = AppState {
        gateway: Arc::new(gateway),
    };

    let app = Router::new()
        .route("/proof", get(handle_proof_request))
        .with_state(state);

    let addr: SocketAddr = "[::]:8080".parse()?;
    println!("Listening on {}", addr);

    axum::serve(
        tokio::net::TcpListener::bind(&addr).await?,
        app.into_make_service(),
    )
    .await?;

    Ok(())
}
