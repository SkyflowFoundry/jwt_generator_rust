use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Deserialize)]
struct Credentials {
    clientID: String,
    keyID: String,
    tokenURI: String,
    privateKey: String,
}

#[derive(Serialize)]
struct Claims {
    iss: String,
    key: String,
    aud: String,
    exp: usize,
    sub: String,
}

fn get_signed_jwt(creds_file: &str) -> (String, Credentials) {
    // Read and parse credentials.json
    let mut file = File::open(creds_file).expect("Unable to open credentials file");
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .expect("Unable to read credentials file");
    let creds: Credentials = serde_json::from_str(&contents).expect("Invalid JSON format");

    // Create claims
    let expiration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs() as usize
        + 3600; // JWT expires in 60 minutes

    let claims = Claims {
        iss: creds.clientID.clone(),
        key: creds.keyID.clone(),
        aud: creds.tokenURI.clone(),
        exp: expiration,
        sub: creds.clientID.clone(),
    };

    // Sign the JWT
    let header = Header::new(Algorithm::RS256);
    let private_key = EncodingKey::from_rsa_pem(creds.privateKey.as_bytes())
        .expect("Invalid private key format");
    let signed_jwt = encode(&header, &claims, &private_key).expect("Failed to sign JWT");

    (signed_jwt, creds)
}

fn get_bearer_token(signed_jwt: &str, creds: &Credentials) -> String {
    // Create the request body
    let body = serde_json::json!({
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": signed_jwt,
    });

    // Make the HTTP POST request
    let client = Client::new();
    let response = client
        .post(&creds.tokenURI)
        .json(&body)
        .send()
        .expect("Failed to send request");

    if response.status().is_success() {
        response
            .text()
            .expect("Failed to read response text")
    } else {
        panic!("Request failed with status: {}", response.status());
    }
}

fn main() {
    let creds_file = "<REPLACE_CREDENTIALS_JSON>";
    let (jwt_token, creds) = get_signed_jwt(creds_file);
    let bearer_token = get_bearer_token(&jwt_token, &creds);
    println!("{}", bearer_token);
}
