use std::{
    collections::HashMap,
    fs::File,
    io::{BufRead as _, BufReader, Read},
    path::Path,
};

use anyhow::{anyhow, Context, Result};
use pwhash::unix;

use lightway_server::{ServerAuth, ServerAuthResult};

#[derive(Debug)]
pub struct Auth {
    db: HashMap<String, String>,
}

impl Auth {
    pub fn new(path: &Path) -> Result<Self> {
        Self::from_reader(File::open(path)?).with_context(|| format!("Parsing {}", path.display()))
    }

    pub fn from_reader(r: impl Read) -> Result<Self> {
        let f = BufReader::new(r);
        let db: HashMap<String, String> = f
            .lines()
            .enumerate()
            .map(|(nr, line)| {
                let line = match line {
                    Ok(line) => line,
                    Err(err) => return Err(anyhow!(err)),
                };

                let Some((user, hash)) = line.split_once(":") else {
                    return Err(anyhow!("Failed to parse line {}", nr + 1));
                };

                if user.is_empty() {
                    return Err(anyhow!("No user found in line {}", nr + 1));
                }
                if hash.is_empty() {
                    return Err(anyhow!("No password hash found in line {}", nr + 1));
                }

                Ok((user.to_string(), hash.to_string()))
            })
            .collect::<Result<_>>()?;

        if db.is_empty() {
            return Err(anyhow!("No users found in user db"));
        }

        Ok(Self { db })
    }
}

impl<AS> ServerAuth<AS> for Auth {
    fn authorize_user_password(
        &self,
        user: &str,
        password: &str,
        _app_state: &mut AS,
    ) -> ServerAuthResult {
        let Some(hash) = self.db.get(user) else {
            tracing::info!(?user, "User not found");
            return ServerAuthResult::Denied;
        };

        if unix::verify(password, hash) {
            ServerAuthResult::Granted {
                handle: None,
                tunnel_protocol_version: None,
            }
        } else {
            tracing::info!(?user, "Invalid password");
            ServerAuthResult::Denied
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use test_case::test_case;

    use super::*;

    #[test_case(b"" => panics "No users found in user db")]
    #[test_case(b"xxx" => panics "Failed to parse line 1")]
    #[test_case(b":hash" => panics "No user found in line 1")]
    #[test_case(b"user:" => panics "No password hash found in line 1")]
    #[test_case(b"user:hash\n" => 1)]
    #[test_case(b"user:hash\nanother:user" => 2)]
    #[test_case(b"user:hash\nuser:hash2" => 1)]
    #[test_case(b"\xc3\x28" => panics "stream did not contain valid UTF-8")]
    fn parsing_password_files(db: &[u8]) -> usize {
        let db = Auth::from_reader(Cursor::new(db)).unwrap();
        db.db.len()
    }

    // Contains:
    // bcrypt_user: bcrypt_password
    // sha256_user: sha256_password
    // sha512_user: sha512_password
    // bad_hash_user: Not valid
    // apachemd5_user: apachemd5_password
    // no

    const LWPASSWD: &str = r"bcrypt_user:$2y$05$sLC0IaxaPbphGjLzmTEb8eDL9NL/tiBfA7OTVpa1CfDkUkW9CVTuO
sha256_user:$5$iossVgDQrSn1S35f$A08tsmhi863Ir5vJEbF1iHjnDOc8lpspzYxKWzY4Uy7
sha512_user:$5$Syjorkmkhi4MiC22$ssGjWYeevMgdkskpduH1nWbmC4suxQNUl82SYJ2XK42
bad_hash_user:NOT A HASH
apachemd5_user:$apr1$dzIISjZV$itIp3R9OU32h.vQ0tm9rm/";
    #[test_case("bcrypt_user", "bcrypt_password" => matches ServerAuthResult::Granted{..} )]
    #[test_case("sha256_user", "sha256_password" => matches ServerAuthResult::Granted{..} )]
    #[test_case("sha512_user", "sha512_password" => matches ServerAuthResult::Granted{..} )]
    #[test_case("bad_hash_user", "n/a" => matches ServerAuthResult::Denied )]
    #[test_case("apachemd5_user", "apachemd5_passwd" => matches ServerAuthResult::Denied )]
    fn authorizing(user: &str, pass: &str) -> ServerAuthResult {
        let db = Auth::from_reader(Cursor::new(LWPASSWD)).unwrap();
        assert_eq!(db.db.len(), 5);
        db.authorize_user_password(user, pass, &mut ())
    }
}
