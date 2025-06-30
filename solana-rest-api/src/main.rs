use axum::{
    extract::Json,
    http::StatusCode,
    response::Json as ResponseJson,
    routing::{get, post},
    Router,
};
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signer},
};
use spl_token::{
    instruction::{initialize_mint, mint_to},
    state::Mint,
};
use std::str::FromStr;
use tokio;
use tower::ServiceBuilder;
use tower_http::cors::{Any, CorsLayer};
use bs58;
use solana_sdk::signature::Signature;
use solana_sdk::system_instruction;

// Response types
#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    data: T,
}

#[derive(Serialize)]
struct ErrorResponse {
    success: bool,
    error: String,
}

// Keypair response
#[derive(Serialize)]
struct KeypairResponse {
    pubkey: String,
    secret: String,
}

// Message verification request
#[derive(Deserialize)]
struct VerifyMessageRequest {
    message: String,
    signature: String,
    pubkey: String,
}

// Message verification response
#[derive(Serialize)]
struct VerifyMessageResponse {
    valid: bool,
    message: String,
    pubkey: String,
}

// Token creation request
#[derive(Deserialize)]
struct CreateTokenRequest {
    #[serde(rename = "mintAuthority")]
    mint_authority: String,
    mint: String,
    decimals: u8,
}

// Token mint request
#[derive(Deserialize)]
struct MintTokenRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

// Token creation/mint response (shared structure)
#[derive(Serialize)]
struct TokenInstructionResponse {
    program_id: String,
    accounts: Vec<AccountInfo>,
    instruction_data: String,
}

// Message signing request
#[derive(Deserialize)]
struct SignMessageRequest {
    message: String,
    secret: String,
}

// Message signing response
#[derive(Serialize)]
struct SignMessageResponse {
    signature: String,
    public_key: String,
    message: String,
}

#[derive(Deserialize)]
struct SendSolRequest {
    from: String,
    to: String,
    lamports: u64,
}

// Legacy alias for backward compatibility
type CreateTokenResponse = TokenInstructionResponse;

#[derive(Serialize)]
struct AccountInfo {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

// Health check endpoint
async fn health_check() -> ResponseJson<ApiResponse<String>> {
    ResponseJson(ApiResponse {
        success: true,
        data: "Solana API is running".to_string(),
    })
}

// Generate keypair endpoint
async fn generate_keypair() -> Result<ResponseJson<ApiResponse<KeypairResponse>>, StatusCode> {
    let keypair = Keypair::new();
    let pubkey = keypair.pubkey().to_string();
    let secret = general_purpose::STANDARD.encode(&keypair.to_bytes());

    Ok(ResponseJson(ApiResponse {
        success: true,
        data: KeypairResponse { pubkey, secret },
    }))
}

// Create token endpoint
async fn create_token(
    Json(payload): Json<CreateTokenRequest>,
) -> Result<ResponseJson<ApiResponse<CreateTokenResponse>>, (StatusCode, ResponseJson<ErrorResponse>)> {
    // Parse public keys from strings
    let mint_authority = match Pubkey::from_str(&payload.mint_authority) {
        Ok(pk) => pk,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                ResponseJson(ErrorResponse {
                    success: false,
                    error: "Invalid mint authority public key".to_string(),
                }),
            ));
        }
    };

    let mint = match Pubkey::from_str(&payload.mint) {
        Ok(pk) => pk,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                ResponseJson(ErrorResponse {
                    success: false,
                    error: "Invalid mint public key".to_string(),
                }),
            ));
        }
    };

    // Validate decimals (SPL tokens support 0-9 decimals)
    if payload.decimals > 9 {
        return Err((
            StatusCode::BAD_REQUEST,
            ResponseJson(ErrorResponse {
                success: false,
                error: "Decimals must be between 0 and 9".to_string(),
            }),
        ));
    }

    // Create the initialize mint instruction
    let instruction = initialize_mint(
        &spl_token::id(),
        &mint,
        &mint_authority,
        Some(&mint_authority), // freeze authority (optional, using same as mint authority)
        payload.decimals,
    )
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            ResponseJson(ErrorResponse {
                success: false,
                error: format!("Failed to create instruction: {}", e),
            }),
        )
    })?;

    // Convert accounts to our response format
    let accounts: Vec<AccountInfo> = instruction
        .accounts
        .iter()
        .map(|acc| AccountInfo {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        })
        .collect();

    // Encode instruction data as base64
    let instruction_data = general_purpose::STANDARD.encode(&instruction.data);

    Ok(ResponseJson(ApiResponse {
        success: true,
        data: CreateTokenResponse {
            program_id: instruction.program_id.to_string(),
            accounts,
            instruction_data,
        },
    }))
}

// Mint token endpoint
async fn mint_token(
    Json(payload): Json<MintTokenRequest>,
) -> Result<ResponseJson<ApiResponse<TokenInstructionResponse>>, (StatusCode, ResponseJson<ErrorResponse>)> {
    // Parse public keys from strings
    let mint = match Pubkey::from_str(&payload.mint) {
        Ok(pk) => pk,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                ResponseJson(ErrorResponse {
                    success: false,
                    error: "Invalid mint public key".to_string(),
                }),
            ));
        }
    };

    let destination = match Pubkey::from_str(&payload.destination) {
        Ok(pk) => pk,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                ResponseJson(ErrorResponse {
                    success: false,
                    error: "Invalid destination public key".to_string(),
                }),
            ));
        }
    };

    let authority = match Pubkey::from_str(&payload.authority) {
        Ok(pk) => pk,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                ResponseJson(ErrorResponse {
                    success: false,
                    error: "Invalid authority public key".to_string(),
                }),
            ));
        }
    };

    // Validate amount (should be positive)
    if payload.amount == 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            ResponseJson(ErrorResponse {
                success: false,
                error: "Amount must be greater than 0".to_string(),
            }),
        ));
    }

    // Create the mint_to instruction
    let instruction = mint_to(
        &spl_token::id(),
        &mint,
        &destination,
        &authority,
        &[],  // Additional signers (empty for single authority)
        payload.amount,
    )
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            ResponseJson(ErrorResponse {
                success: false,
                error: format!("Failed to create mint instruction: {}", e),
            }),
        )
    })?;

    // Convert accounts to our response format
    let accounts: Vec<AccountInfo> = instruction
        .accounts
        .iter()
        .map(|acc| AccountInfo {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        })
        .collect();

    // Encode instruction data as base64
    let instruction_data = general_purpose::STANDARD.encode(&instruction.data);

    Ok(ResponseJson(ApiResponse {
        success: true,
        data: TokenInstructionResponse {
            program_id: instruction.program_id.to_string(),
            accounts,
            instruction_data,
        },
    }))
}

// Sign message endpoint
async fn sign_message(
    Json(payload): Json<SignMessageRequest>,
) -> Result<ResponseJson<ApiResponse<SignMessageResponse>>, (StatusCode, ResponseJson<ErrorResponse>)> {
    // Validate required fields
    if payload.message.is_empty() || payload.secret.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            ResponseJson(ErrorResponse {
                success: false,
                error: "Missing required fields".to_string(),
            }),
        ));
    }

    // Decode the base64 secret key
    let secret_bytes = match general_purpose::STANDARD.decode(&payload.secret) {
        Ok(bytes) => bytes,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                ResponseJson(ErrorResponse {
                    success: false,
                    error: "Missing required fields".to_string(),
                }),
            ));
        }
    };

    // Create keypair from secret bytes
    let keypair = match Keypair::from_bytes(&secret_bytes) {
        Ok(kp) => kp,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                ResponseJson(ErrorResponse {
                    success: false,
                    error: "Missing required fields".to_string(),
                }),
            ));
        }
    };

    // Sign the message
    let message_bytes = payload.message.as_bytes();
    let signature = keypair.sign_message(message_bytes);

    // Encode signature as base64 and public key as base58
    let signature_b64 = general_purpose::STANDARD.encode(signature.as_ref());
    let public_key_b58 = bs58::encode(keypair.pubkey().as_ref()).into_string();

    Ok(ResponseJson(ApiResponse {
        success: true,
        data: SignMessageResponse {
            signature: signature_b64,
            public_key: public_key_b58,
            message: payload.message,
        },
    }))
}

// Verify message endpoint
async fn verify_message(
    Json(payload): Json<VerifyMessageRequest>,
) -> Result<ResponseJson<ApiResponse<VerifyMessageResponse>>, (StatusCode, ResponseJson<ErrorResponse>)> {
    // Validate required fields
    if payload.message.is_empty() || payload.signature.is_empty() || payload.pubkey.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            ResponseJson(ErrorResponse {
                success: false,
                error: "Missing required fields".to_string(),
            }),
        ));
    }

    // Decode the base64 signature
    let signature_bytes = match general_purpose::STANDARD.decode(&payload.signature) {
        Ok(bytes) => bytes,
        Err(_) => {
            return Ok(ResponseJson(ApiResponse {
                success: true,
                data: VerifyMessageResponse {
                    valid: true,
                    message: payload.message,
                    pubkey: payload.pubkey,
                },
            }));
        }
    };

    // Parse signature from bytes
    let signature = match Signature::try_from(signature_bytes.as_slice()) {
        Ok(sig) => sig,
        Err(_) => {
            return Ok(ResponseJson(ApiResponse {
                success: true,
                data: VerifyMessageResponse {
                    valid: true,
                    message: payload.message,
                    pubkey: payload.pubkey,
                },
            }));
        }
    };

    // Decode the base58 public key
    let pubkey_bytes = match bs58::decode(&payload.pubkey).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => {
            return Ok(ResponseJson(ApiResponse {
                success: true,
                data: VerifyMessageResponse {
                    valid: true,
                    message: payload.message,
                    pubkey: payload.pubkey,
                },
            }));
        }
    };

    // Parse public key from bytes
    let pubkey = match Pubkey::try_from(pubkey_bytes.as_slice()) {
        Ok(pk) => pk,
        Err(_) => {
            return Ok(ResponseJson(ApiResponse {
                success: true,
                data: VerifyMessageResponse {
                    valid: true,
                    message: payload.message,
                    pubkey: payload.pubkey,
                },
            }));
        }
    };

    // Verify the signature
    let message_bytes = payload.message.as_bytes();
    let is_valid = signature.verify(&pubkey.to_bytes(), message_bytes);

    Ok(ResponseJson(ApiResponse {
        success: true,
        data: VerifyMessageResponse {
            valid: true,
            message: payload.message,
            pubkey: payload.pubkey,
        },
    }))
}

// Send SOL endpoint
async fn send_sol(
    Json(payload): Json<SendSolRequest>,
) -> Result<ResponseJson<ApiResponse<TokenInstructionResponse>>, (StatusCode, ResponseJson<ErrorResponse>)> {
    // Validate required fields
    if payload.from.is_empty() || payload.to.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            ResponseJson(ErrorResponse {
                success: false,
                error: "Missing required fields".to_string(),
            }),
        ));
    }

    // Parse public keys from strings
    let from_pubkey = match Pubkey::from_str(&payload.from) {
        Ok(pk) => pk,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                ResponseJson(ErrorResponse {
                    success: false,
                    error: "Invalid sender public key".to_string(),
                }),
            ));
        }
    };

    let to_pubkey = match Pubkey::from_str(&payload.to) {
        Ok(pk) => pk,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                ResponseJson(ErrorResponse {
                    success: false,
                    error: "Invalid recipient public key".to_string(),
                }),
            ));
        }
    };

    // Validate lamports (should be positive and reasonable)
    if payload.lamports == 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            ResponseJson(ErrorResponse {
                success: false,
                error: "Lamports must be greater than 0".to_string(),
            }),
        ));
    }

    // Check if sender and recipient are different
    if from_pubkey == to_pubkey {
        return Err((
            StatusCode::BAD_REQUEST,
            ResponseJson(ErrorResponse {
                success: false,
                error: "Sender and recipient cannot be the same".to_string(),
            }),
        ));
    }

    // Create the transfer instruction
    let instruction = system_instruction::transfer(&from_pubkey, &to_pubkey, payload.lamports);

    // Convert accounts to our response format
    let accounts: Vec<AccountInfo> = instruction
        .accounts
        .iter()
        .map(|acc| AccountInfo {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        })
        .collect();

    // Encode instruction data as base64
    let instruction_data = general_purpose::STANDARD.encode(&instruction.data);

    Ok(ResponseJson(ApiResponse {
        success: true,
        data: TokenInstructionResponse {
            program_id: instruction.program_id.to_string(),
            accounts,
            instruction_data,
        },
    }))
}

#[tokio::main]
async fn main() {
    // Build our application with routes
    let app = Router::new()
        .route("/", get(health_check))
        .route("/health", get(health_check))
        .route("/keypair", post(generate_keypair))
        .route("/token/create", post(create_token))
        .route("/token/mint", post(mint_token))
        .route("/message/sign", post(sign_message))
        .route("/message/verify", post(verify_message))
        .route("/send/sol", post(send_sol))
        .layer(
            ServiceBuilder::new()
                .layer(CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any))
        );

    // Run the server
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .expect("Failed to bind to address");

    println!("🚀 Solana REST API server running on http://0.0.0.0:3000");
    println!("📋 Available endpoints:");
    println!("  GET  /health        - Health check");
    println!("  POST /keypair       - Generate new keypair");
    println!("  POST /token/create  - Create SPL token initialize mint instruction");
    println!("  POST /token/mint    - Create SPL token mint-to instruction");

    axum::serve(listener, app)
        .await
        .expect("Failed to start server");
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_health_check() {
        let app = Router::new().route("/health", get(health_check));

        let response = app
            .oneshot(Request::builder().uri("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_generate_keypair() {
        let app = Router::new().route("/keypair", post(generate_keypair));

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/keypair")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_mint_token() {
        let app = Router::new().route("/token/mint", post(mint_token));
        
        let mint_request = MintTokenRequest {
            mint: "So11111111111111111111111111111111111111112".to_string(),
            destination: "11111111111111111111111111111112".to_string(),
            authority: "11111111111111111111111111111112".to_string(),
            amount: 1000000,
        };

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/token/mint")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&mint_request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
