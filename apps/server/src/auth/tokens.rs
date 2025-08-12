use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use jsonwebtoken as jwt;

#[derive(Debug, Serialize, Deserialize)]
pub struct Cnf { pub jkt: String }

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub iat: i64,
    pub exp: i64,
    pub cnf: Option<Cnf>,
}

pub fn issue_access(sub: &str, jkt: Option<String>, secret: &str, minutes: i64) -> anyhow::Result<(String, i64)> {
    let now = OffsetDateTime::now_utc();
    let exp = now + Duration::minutes(minutes);
    let claims = Claims { sub: sub.to_string(), iat: now.unix_timestamp(), exp: exp.unix_timestamp(), cnf: jkt.map(|j| Cnf { jkt: j }) };
    let token = jwt::encode(&jwt::Header::default(), &claims, &jwt::EncodingKey::from_secret(secret.as_bytes()))?;
    Ok((token, exp.unix_timestamp()))
}

pub fn decode(token: &str, secret: &str) -> anyhow::Result<jwt::TokenData<Claims>> {
    let key = jwt::DecodingKey::from_secret(secret.as_bytes());
    let validation = jwt::Validation::default();
    Ok(jwt::decode::<Claims>(token, &key, &validation)?)
}
