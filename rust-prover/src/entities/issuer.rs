use crate::{
    MAX_CREDENTIALS, Sha256Digest, data_structures::credential::Credential,
    utils::utils::string_to_bytes,
};

pub struct Issuer {
    pub id: [u8; 32],
    credentials: Vec<Credential>, // Issuer가 발급한 모든 Credential. MAX_CREDENTIALS로 제한
    hashed_credentials: Vec<Sha256Digest>, // Issuer가 발급한 Credential의 SHA256 해시 리스트. MAX_CREDENTIALS로 제한
}

impl Issuer {
    pub fn new(id: &str) -> Self {
        Issuer {
            id: string_to_bytes(id),
            credentials: vec![],
            hashed_credentials: vec![],
        }
    }

    // Credential 발급. 최대 MAX_CREDENTIALS 개까지 발급 가능. hashed_credentials에 credential의 SHA256 해시 저장 후 publish
    pub fn issue_credential(&mut self, cred: &Credential) -> Result<(), IssuerError> {
        if self.credentials.len() >= MAX_CREDENTIALS {
            return Err(IssuerError::MaxCredentialsReached);
        }

        self.credentials.push(cred.clone());
        let hashed_credential = cred.to_sha256();
        self.hashed_credentials.push(hashed_credential);
        Ok(())
    }

    pub fn credentials(&self) -> Result<Vec<Credential>, IssuerError> {
        if self.credentials.len() != MAX_CREDENTIALS {
            return Err(IssuerError::IncompleteList);
        }
        Ok(self.credentials.clone())
    }

    pub fn hashed_credentials(&self) -> Result<Vec<Sha256Digest>, IssuerError> {
        if self.hashed_credentials.len() != MAX_CREDENTIALS {
            return Err(IssuerError::IncompleteList);
        }
        Ok(self.hashed_credentials.clone())
    }
}

#[derive(Debug, Clone)]
pub enum IssuerError {
    MaxCredentialsReached, // Issuer가 발급할 수 있는 Credential의 최대 개수 도달
    IncompleteList,        // 리스트의 원소 개수 부족
}
