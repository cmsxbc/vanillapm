use crate::framework::{DataManager, Item};

use openssl;
use rand;
use rand::RngCore;
use rpassword;
use sqlite;
use std::error::Error;

#[cfg(test)]
use std::path::PathBuf;

const SALT_SIZE: usize = 333;
const KDF_SALT_SIZE: usize = 32;
const HMAC_KEY_SIZE: usize = 32;
#[cfg(not(test))]
const PBKDF2_ITERATIONS: usize = 600_000;
#[cfg(test)]
const PBKDF2_ITERATIONS: usize = 1;
const AES_IV_SIZE: usize = 16;
const AES_KEY_SIZE: usize = 32;

#[cfg(not(test))]
const RSA_KEY_SIZE: u32 = 8192;
#[cfg(test)]
const RSA_KEY_SIZE: u32 = 4096;

pub struct SQLiteManager {
    connection: sqlite::Connection,
    pubkey: openssl::rsa::Rsa<openssl::pkey::Public>,
    prikey: openssl::rsa::Rsa<openssl::pkey::Private>,
    hmac_key: Vec<u8>,
}

fn derive_key(password: &[u8], salt: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut key = vec![0u8; AES_KEY_SIZE];
    openssl::pkcs5::pbkdf2_hmac(
        password,
        salt,
        PBKDF2_ITERATIONS,
        openssl::hash::MessageDigest::sha256(),
        &mut key,
    )?;
    Ok(key)
}

fn aes_encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let cipher = openssl::symm::Cipher::aes_256_cbc();
    let mut iv = vec![0u8; AES_IV_SIZE];
    rand::thread_rng().fill_bytes(&mut iv);
    let ciphertext = openssl::symm::encrypt(cipher, key, Some(&iv), plaintext)?;
    let mut result = iv;
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

fn aes_decrypt(key: &[u8], iv_and_ciphertext: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    if iv_and_ciphertext.len() <= AES_IV_SIZE {
        return Err("Invalid encrypted data: too short".into());
    }
    let cipher = openssl::symm::Cipher::aes_256_cbc();
    let (iv, ciphertext) = iv_and_ciphertext.split_at(AES_IV_SIZE);
    let plaintext = openssl::symm::decrypt(cipher, key, Some(iv), ciphertext)?;
    Ok(plaintext)
}

fn compute_hmac(key: &[u8], data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let pkey = openssl::pkey::PKey::hmac(key)?;
    let mut signer = openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &pkey)?;
    signer.update(data)?;
    Ok(signer.sign_to_vec()?)
}

type KeySet = (
    openssl::rsa::Rsa<openssl::pkey::Public>,
    openssl::rsa::Rsa<openssl::pkey::Private>,
    Vec<u8>,
);

impl SQLiteManager {
    pub fn is_v2(connection: &sqlite::Connection) -> bool {
        if let Ok(stmt) = connection.prepare("SELECT 1 FROM vanillapm WHERE s='vanillapm_v2'") {
            let mut cursor = stmt.into_cursor();
            if let Ok(row) = cursor.try_next() {
                return row.is_some();
            }
        }
        false
    }

    pub fn is_legacy(connection: &sqlite::Connection) -> bool {
        if let Ok(stmt) = connection.prepare("SELECT 1 FROM vanillapm WHERE s='vanillapm'") {
            let mut cursor = stmt.into_cursor();
            if let Ok(row) = cursor.try_next() {
                return row.is_some();
            }
        }
        false
    }

    fn read_blob(connection: &sqlite::Connection, key: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut cursor = connection
            .prepare("SELECT a FROM vanillapm WHERE s = ?")?
            .bind(1, key)?
            .into_cursor();
        match cursor.try_next()? {
            Some(values) => Ok(values[0].as_binary().unwrap().to_vec()),
            None => Err(format!("Missing key in vanillapm: {}", key).into()),
        }
    }

    fn load_keys(
        connection: &sqlite::Connection,
        password: &str,
    ) -> Result<KeySet, Box<dyn Error>> {
        let kdf_salt = Self::read_blob(connection, "kdf_salt")?;
        let aes_key = derive_key(password.as_bytes(), &kdf_salt)?;

        let prikey_enc = Self::read_blob(connection, "prikey")?;
        let prikey_pem = aes_decrypt(&aes_key, &prikey_enc)?;
        let prikey = openssl::rsa::Rsa::private_key_from_pem(&prikey_pem)?;

        let pubkey_pem = Self::read_blob(connection, "pubkey")?;
        let pubkey = openssl::rsa::Rsa::public_key_from_pem_pkcs1(&pubkey_pem)?;

        let hmac_key_enc = Self::read_blob(connection, "hmac_key")?;
        let hmac_key = aes_decrypt(&aes_key, &hmac_key_enc)?;

        Ok((pubkey, prikey, hmac_key))
    }

    fn init_db(connection: &sqlite::Connection) -> Result<String, Box<dyn Error>> {
        match connection
            .prepare("SELECT COUNT(*) FROM vanillapm")
            .unwrap()
            .into_cursor()
            .next()
        {
            Some(Ok(r)) => {
                if r.get::<i64, _>(0) != 0 {
                    return Err("Invalid db file!".into());
                }
            }
            Some(Err(err)) => return Err(err.into()),
            None => (),
        }
        println!("Init db!");

        let password = rpassword::prompt_password("password>")?;
        let confirm_password = rpassword::prompt_password("confirm password>")?;
        if password != confirm_password {
            return Err("password mismatch".into());
        }

        // Generate RSA keypair
        let keypair = openssl::rsa::Rsa::generate(RSA_KEY_SIZE)?;
        let pubkey_pem = keypair.public_key_to_pem_pkcs1()?;
        let prikey_pem = keypair.private_key_to_pem()?;

        // Generate random HMAC key for site name indexing
        let mut hmac_key = vec![0u8; HMAC_KEY_SIZE];
        rand::thread_rng().fill_bytes(&mut hmac_key);

        // Derive AES-256 key from password via PBKDF2-HMAC-SHA256 (600k iterations)
        let mut kdf_salt = vec![0u8; KDF_SALT_SIZE];
        rand::thread_rng().fill_bytes(&mut kdf_salt);
        let aes_key = derive_key(password.as_bytes(), &kdf_salt)?;

        // Encrypt private key and HMAC key with derived AES key
        let prikey_enc = aes_encrypt(&aes_key, &prikey_pem)?;
        let hmac_key_enc = aes_encrypt(&aes_key, &hmac_key)?;

        // Store version marker
        connection.execute("INSERT INTO vanillapm VALUES ('vanillapm_v2', NULL, NULL)")?;

        // Store public key
        connection
            .prepare("INSERT INTO vanillapm VALUES ('pubkey', ?, NULL)")?
            .bind(1, pubkey_pem.as_slice())?
            .next()?;

        // Store KDF salt
        connection
            .prepare("INSERT INTO vanillapm VALUES ('kdf_salt', ?, NULL)")?
            .bind(1, kdf_salt.as_slice())?
            .next()?;

        // Store encrypted private key
        connection
            .prepare("INSERT INTO vanillapm VALUES ('prikey', ?, NULL)")?
            .bind(1, prikey_enc.as_slice())?
            .next()?;

        // Store encrypted HMAC key
        connection
            .prepare("INSERT INTO vanillapm VALUES ('hmac_key', ?, NULL)")?
            .bind(1, hmac_key_enc.as_slice())?
            .next()?;

        Ok(password)
    }

    /// Initialize a new v2 database with the given password (non-interactive).
    /// Used by tests and by `new_init_with_passwd`.
    fn init_db_with_passwd(
        connection: &sqlite::Connection,
        password: &str,
    ) -> Result<(), Box<dyn Error>> {
        // Generate RSA keypair
        let keypair = openssl::rsa::Rsa::generate(RSA_KEY_SIZE)?;
        let pubkey_pem = keypair.public_key_to_pem_pkcs1()?;
        let prikey_pem = keypair.private_key_to_pem()?;

        // Generate random HMAC key for site name indexing
        let mut hmac_key = vec![0u8; HMAC_KEY_SIZE];
        rand::thread_rng().fill_bytes(&mut hmac_key);

        // Derive AES-256 key from password via PBKDF2-HMAC-SHA256
        let mut kdf_salt = vec![0u8; KDF_SALT_SIZE];
        rand::thread_rng().fill_bytes(&mut kdf_salt);
        let aes_key = derive_key(password.as_bytes(), &kdf_salt)?;

        // Encrypt private key and HMAC key with derived AES key
        let prikey_enc = aes_encrypt(&aes_key, &prikey_pem)?;
        let hmac_key_enc = aes_encrypt(&aes_key, &hmac_key)?;

        // Store version marker
        connection.execute("INSERT INTO vanillapm VALUES ('vanillapm_v2', NULL, NULL)")?;

        // Store public key
        connection
            .prepare("INSERT INTO vanillapm VALUES ('pubkey', ?, NULL)")?
            .bind(1, pubkey_pem.as_slice())?
            .next()?;

        // Store KDF salt
        connection
            .prepare("INSERT INTO vanillapm VALUES ('kdf_salt', ?, NULL)")?
            .bind(1, kdf_salt.as_slice())?
            .next()?;

        // Store encrypted private key
        connection
            .prepare("INSERT INTO vanillapm VALUES ('prikey', ?, NULL)")?
            .bind(1, prikey_enc.as_slice())?
            .next()?;

        // Store encrypted HMAC key
        connection
            .prepare("INSERT INTO vanillapm VALUES ('hmac_key', ?, NULL)")?
            .bind(1, hmac_key_enc.as_slice())?
            .next()?;

        Ok(())
    }

    /// Create a brand-new v2 database initialized with the given password (non-interactive).
    /// This is useful for tests and for the migration path where the password is already known.
    pub fn new_init_with_passwd(
        filepath: &str,
        key_filepath: &Option<String>,
        password: &str,
    ) -> Result<Self, Box<dyn Error>> {
        let connection = sqlite::open(filepath)?;
        let temp_connection;
        let key_connection = if let Some(key_db) = key_filepath {
            temp_connection = sqlite::open(key_db)?;
            Some(&temp_connection)
        } else {
            None
        };

        let kc = key_connection.unwrap_or(&connection);
        kc.execute("CREATE TABLE IF NOT EXISTS vanillapm (s TEXT, a BLOB, p BLOB)")?;
        connection.execute("CREATE TABLE IF NOT EXISTS data (sh BLOB, s BLOB, a BLOB, p BLOB)")?;

        Self::init_db_with_passwd(kc, password)?;

        let (pubkey, prikey, hmac_key) = Self::load_keys(kc, password)?;
        Ok(SQLiteManager {
            connection,
            pubkey,
            prikey,
            hmac_key,
        })
    }

    fn add_salt(mut data: Vec<u8>) -> Vec<u8> {
        let mut ret = vec![0u8; SALT_SIZE];
        rand::thread_rng().fill_bytes(&mut ret);
        ret.append(&mut data);
        ret
    }

    fn rsa_encrypt(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let salted = Self::add_salt(data.to_vec());
        let mut encrypted = vec![0u8; self.pubkey.size() as usize];
        self.pubkey
            .public_encrypt(&salted, &mut encrypted, openssl::rsa::Padding::PKCS1_OAEP)?;
        Ok(encrypted)
    }

    fn rsa_decrypt(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut decrypted = vec![0u8; self.prikey.size() as usize];
        let len =
            self.prikey
                .private_decrypt(data, &mut decrypted, openssl::rsa::Padding::PKCS1_OAEP)?;
        decrypted.truncate(len);
        if decrypted.len() < SALT_SIZE {
            return Err("Decrypted data too short: invalid salt".into());
        }
        Ok(decrypted[SALT_SIZE..].to_vec())
    }

    fn insert(&self, item: &Item) -> Result<(), Box<dyn Error>> {
        let site_hmac = compute_hmac(&self.hmac_key, item.site.as_bytes())?;
        let site_enc = self.rsa_encrypt(item.site.as_bytes())?;
        let account_enc = self.rsa_encrypt(item.account.as_bytes())?;
        let password_enc = self.rsa_encrypt(item.password.as_bytes())?;

        self.connection
            .prepare("INSERT INTO data VALUES (?, ?, ?, ?)")?
            .bind(1, site_hmac.as_slice())?
            .bind(2, site_enc.as_slice())?
            .bind(3, account_enc.as_slice())?
            .bind(4, password_enc.as_slice())?
            .next()?;
        Ok(())
    }

    fn decrypt_item(&self, values: &[sqlite::Value]) -> Result<Item, Box<dyn Error>> {
        // values[0] = sh (HMAC hash, skip)
        // values[1] = s  (RSA-OAEP encrypted site)
        // values[2] = a  (RSA-OAEP encrypted account)
        // values[3] = p  (RSA-OAEP encrypted password)
        let site = String::from_utf8(self.rsa_decrypt(values[1].as_binary().unwrap())?)?;
        let account = String::from_utf8(self.rsa_decrypt(values[2].as_binary().unwrap())?)?;
        let password = String::from_utf8(self.rsa_decrypt(values[3].as_binary().unwrap())?)?;
        Ok(Item {
            site,
            account,
            password,
        })
    }

    fn get_item(&self, mut cursor: sqlite::Cursor) -> Result<Option<Item>, Box<dyn Error>> {
        if let Some(values) = cursor.try_next()? {
            Ok(Some(self.decrypt_item(values)?))
        } else {
            Ok(None)
        }
    }

    fn get_items(&self, mut cursor: sqlite::Cursor) -> Result<Option<Vec<Item>>, Box<dyn Error>> {
        let mut items: Vec<Item> = vec![];
        while let Some(values) = cursor.try_next()? {
            items.push(self.decrypt_item(values)?);
        }
        Ok(Some(items))
    }

    pub fn get_all_items(&self) -> Result<Option<Vec<Item>>, Box<dyn Error>> {
        let cursor = self
            .connection
            .prepare("SELECT sh, s, a, p FROM data")?
            .into_cursor();
        self.get_items(cursor)
    }
}

impl DataManager for SQLiteManager {
    fn new(filepath: &str, key_filepath: &Option<String>) -> Result<Self, Box<dyn Error>> {
        let connection = sqlite::open(filepath)?;
        let temp_connection;
        let key_connection = if let Some(key_db) = key_filepath {
            temp_connection = sqlite::open(key_db)?;
            Some(&temp_connection)
        } else {
            None
        };

        println!("Welcome to vanillapm!");

        let kc = key_connection.unwrap_or(&connection);
        kc.execute("CREATE TABLE IF NOT EXISTS vanillapm (s TEXT, a BLOB, p BLOB)")
            .unwrap();

        if Self::is_legacy(kc) {
            return Err(
                "This database uses the legacy format. Please run the 'migrate' command to upgrade."
                    .into(),
            );
        }

        if Self::is_v2(kc) {
            // Existing v2 database — prompt for password and load keys
            let password = rpassword::prompt_password("password>")?;
            let (pubkey, prikey, hmac_key) = Self::load_keys(kc, &password)?;
            Ok(SQLiteManager {
                connection,
                pubkey,
                prikey,
                hmac_key,
            })
        } else {
            // Brand new database — initialize
            connection
                .execute("CREATE TABLE IF NOT EXISTS data (sh BLOB, s BLOB, a BLOB, p BLOB)")?;
            let password = Self::init_db(kc)?;
            let (pubkey, prikey, hmac_key) = Self::load_keys(kc, &password)?;
            Ok(SQLiteManager {
                connection,
                pubkey,
                prikey,
                hmac_key,
            })
        }
    }

    fn new_with_passwd(
        filepath: &str,
        key_filepath: &Option<String>,
        password: &str,
    ) -> Result<Self, Box<dyn Error>> {
        let connection = sqlite::open(filepath)?;
        let temp_connection;
        let key_connection = if let Some(key_db) = key_filepath {
            temp_connection = sqlite::open(key_db)?;
            Some(&temp_connection)
        } else {
            None
        };

        let kc = key_connection.unwrap_or(&connection);
        kc.execute("CREATE TABLE IF NOT EXISTS vanillapm (s TEXT, a BLOB, p BLOB)")
            .unwrap();

        if Self::is_legacy(kc) {
            return Err(
                "This database uses the legacy format. Please run the 'migrate' command to upgrade."
                    .into(),
            );
        }

        if !Self::is_v2(kc) {
            return Err("Not a valid v2 database".into());
        }

        let (pubkey, prikey, hmac_key) = Self::load_keys(kc, password)?;
        Ok(SQLiteManager {
            connection,
            pubkey,
            prikey,
            hmac_key,
        })
    }

    fn add(&self, item: &Item) -> Result<(), Box<dyn Error>> {
        self.insert(item)
    }

    fn query_one(&self, site: &str) -> Result<Option<Item>, Box<dyn Error>> {
        let site_hmac = compute_hmac(&self.hmac_key, site.as_bytes())?;
        let qstat = self
            .connection
            .prepare("SELECT sh, s, a, p FROM data WHERE sh = ?")?;
        self.get_item(qstat.bind(1, site_hmac.as_slice())?.into_cursor())
    }

    fn query(&self, site: &str) -> Result<Option<Vec<Item>>, Box<dyn Error>> {
        let site_hmac = compute_hmac(&self.hmac_key, site.as_bytes())?;
        let qstat = self
            .connection
            .prepare("SELECT sh, s, a, p FROM data WHERE sh = ?")?;
        self.get_items(qstat.bind(1, site_hmac.as_slice())?.into_cursor())
    }

    fn query_like(&self, site: &str) -> Result<Option<Vec<Item>>, Box<dyn Error>> {
        // With encrypted site names we can no longer use SQL LIKE.
        // Fetch all rows, decrypt site names, and filter in memory.
        let all_items = self.get_all_items()?;
        if let Some(items) = all_items {
            // Strip SQL-style '%' wildcards — callers (list_sites, query_account*)
            // pass "%" to mean "match everything".
            let search = site.replace('%', "");
            if search.is_empty() {
                return Ok(Some(items));
            }
            let search_lower = search.to_lowercase();
            let filtered: Vec<Item> = items
                .into_iter()
                .filter(|item| item.site.to_lowercase().contains(&search_lower))
                .collect();
            Ok(Some(filtered))
        } else {
            Ok(Some(vec![]))
        }
    }

    fn query_account(&self, account: &str) -> Result<Option<Vec<Item>>, Box<dyn Error>> {
        let items = self.get_all_items()?.unwrap_or_default();
        Ok(Some(
            items.into_iter().filter(|x| x.account == account).collect(),
        ))
    }

    fn query_account_like(&self, account: &str) -> Result<Option<Vec<Item>>, Box<dyn Error>> {
        let items = self.get_all_items()?.unwrap_or_default();
        Ok(Some(
            items
                .into_iter()
                .filter(|x| x.account.contains(account))
                .collect(),
        ))
    }

    fn finish(&self) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
}

// ─── Test-only helpers ───────────────────────────────────────────────────────

#[cfg(test)]
fn temp_db_path(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    // Include thread id to avoid collisions in parallel tests
    p.push(format!(
        "vanillapm_test_{}_{:?}.db",
        name,
        std::thread::current().id()
    ));
    p
}

#[cfg(test)]
fn cleanup(path: &PathBuf) {
    let _ = std::fs::remove_file(path);
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Crypto primitive tests ───────────────────────────────────────────

    #[test]
    fn test_derive_key_deterministic() {
        let password = b"hunter2";
        let salt = b"0123456789abcdef0123456789abcdef";
        let k1 = derive_key(password, salt).unwrap();
        let k2 = derive_key(password, salt).unwrap();
        assert_eq!(k1, k2);
        assert_eq!(k1.len(), AES_KEY_SIZE);
    }

    #[test]
    fn test_derive_key_different_passwords_differ() {
        let salt = b"0123456789abcdef0123456789abcdef";
        let k1 = derive_key(b"password1", salt).unwrap();
        let k2 = derive_key(b"password2", salt).unwrap();
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_derive_key_different_salts_differ() {
        let password = b"samepassword";
        let k1 = derive_key(password, b"salt_aaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        let k2 = derive_key(password, b"salt_bbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap();
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_aes_encrypt_decrypt_roundtrip() {
        let key = derive_key(b"testpass", b"0123456789abcdef0123456789abcdef").unwrap();
        let plaintext = b"Hello, world! This is a secret.";
        let ciphertext = aes_encrypt(&key, plaintext).unwrap();

        // Ciphertext should be IV (16 bytes) + at least one AES block
        assert!(ciphertext.len() > AES_IV_SIZE);

        let decrypted = aes_decrypt(&key, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_encrypt_produces_different_ciphertexts() {
        // Because of random IV, two encryptions of the same plaintext should differ
        let key = derive_key(b"key", b"0123456789abcdef0123456789abcdef").unwrap();
        let plaintext = b"same data";
        let c1 = aes_encrypt(&key, plaintext).unwrap();
        let c2 = aes_encrypt(&key, plaintext).unwrap();
        assert_ne!(c1, c2, "Random IV should make ciphertexts differ");

        // But both should decrypt to the same plaintext
        assert_eq!(aes_decrypt(&key, &c1).unwrap(), plaintext);
        assert_eq!(aes_decrypt(&key, &c2).unwrap(), plaintext);
    }

    #[test]
    fn test_aes_decrypt_wrong_key_fails() {
        let key1 = derive_key(b"right", b"0123456789abcdef0123456789abcdef").unwrap();
        let key2 = derive_key(b"wrong", b"0123456789abcdef0123456789abcdef").unwrap();
        let ciphertext = aes_encrypt(&key1, b"secret").unwrap();
        let result = aes_decrypt(&key2, &ciphertext);
        assert!(result.is_err(), "Decryption with wrong key should fail");
    }

    #[test]
    fn test_aes_decrypt_too_short_fails() {
        let key = vec![0u8; AES_KEY_SIZE];
        // Data shorter than or equal to IV size should fail
        let result = aes_decrypt(&key, &[0u8; AES_IV_SIZE]);
        assert!(result.is_err());
        let result2 = aes_decrypt(&key, &[0u8; 5]);
        assert!(result2.is_err());
    }

    #[test]
    fn test_aes_empty_plaintext_roundtrip() {
        let key = derive_key(b"k", b"0123456789abcdef0123456789abcdef").unwrap();
        let ciphertext = aes_encrypt(&key, b"").unwrap();
        let decrypted = aes_decrypt(&key, &ciphertext).unwrap();
        assert_eq!(decrypted, b"");
    }

    #[test]
    fn test_aes_large_plaintext_roundtrip() {
        let key = derive_key(b"k", b"0123456789abcdef0123456789abcdef").unwrap();
        let plaintext = vec![0xABu8; 100_000];
        let ciphertext = aes_encrypt(&key, &plaintext).unwrap();
        let decrypted = aes_decrypt(&key, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_compute_hmac_deterministic() {
        let key = b"hmac-key-value-here-1234";
        let data = b"github.com";
        let h1 = compute_hmac(key, data).unwrap();
        let h2 = compute_hmac(key, data).unwrap();
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 32); // SHA-256 output
    }

    #[test]
    fn test_compute_hmac_different_keys_differ() {
        let h1 = compute_hmac(b"key1", b"data").unwrap();
        let h2 = compute_hmac(b"key2", b"data").unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_compute_hmac_different_data_differ() {
        let key = b"same-key";
        let h1 = compute_hmac(key, b"site-a").unwrap();
        let h2 = compute_hmac(key, b"site-b").unwrap();
        assert_ne!(h1, h2);
    }

    // ── RSA encrypt / decrypt (via SQLiteManager) ────────────────────────

    #[test]
    fn test_rsa_encrypt_decrypt_roundtrip() {
        let path = temp_db_path("rsa_roundtrip");
        cleanup(&path);
        let db_str = path.to_str().unwrap();
        let mgr = SQLiteManager::new_init_with_passwd(db_str, &None, "testpw").unwrap();

        let plaintext = b"my-secret-password-123!@#";
        let encrypted = mgr.rsa_encrypt(plaintext).unwrap();
        let decrypted = mgr.rsa_decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);

        cleanup(&path);
    }

    #[test]
    fn test_rsa_encrypt_produces_different_ciphertexts() {
        let path = temp_db_path("rsa_diff_ct");
        cleanup(&path);
        let db_str = path.to_str().unwrap();
        let mgr = SQLiteManager::new_init_with_passwd(db_str, &None, "pw").unwrap();

        let plaintext = b"same-text";
        let c1 = mgr.rsa_encrypt(plaintext).unwrap();
        let c2 = mgr.rsa_encrypt(plaintext).unwrap();
        // Random salt should make ciphertexts differ
        assert_ne!(c1, c2);

        // Both should decrypt correctly
        assert_eq!(mgr.rsa_decrypt(&c1).unwrap(), plaintext);
        assert_eq!(mgr.rsa_decrypt(&c2).unwrap(), plaintext);

        cleanup(&path);
    }

    // ── Database key loading ─────────────────────────────────────────────

    #[test]
    fn test_load_keys_correct_password() {
        let path = temp_db_path("load_keys_ok");
        cleanup(&path);
        let db_str = path.to_str().unwrap();
        let _mgr = SQLiteManager::new_init_with_passwd(db_str, &None, "correct-pw").unwrap();

        // Re-open the database using load_keys with the same password
        let conn = sqlite::open(db_str).unwrap();
        let result = SQLiteManager::load_keys(&conn, "correct-pw");
        assert!(result.is_ok());
        let (pubkey, prikey, hmac_key) = result.unwrap();
        assert!(pubkey.size() > 0);
        assert!(prikey.size() > 0);
        assert_eq!(hmac_key.len(), HMAC_KEY_SIZE);

        cleanup(&path);
    }

    #[test]
    fn test_load_keys_wrong_password_fails() {
        let path = temp_db_path("load_keys_wrong");
        cleanup(&path);
        let db_str = path.to_str().unwrap();
        let _mgr = SQLiteManager::new_init_with_passwd(db_str, &None, "right-password").unwrap();

        let conn = sqlite::open(db_str).unwrap();
        let result = SQLiteManager::load_keys(&conn, "wrong-password");
        assert!(result.is_err(), "Wrong password should fail to load keys");

        cleanup(&path);
    }

    // ── new_with_passwd ──────────────────────────────────────────────────

    #[test]
    fn test_new_with_passwd_opens_existing_v2() {
        let path = temp_db_path("new_with_pw");
        cleanup(&path);
        let db_str = path.to_str().unwrap().to_string();
        let _mgr = SQLiteManager::new_init_with_passwd(&db_str, &None, "mypass").unwrap();
        drop(_mgr);

        let mgr = SQLiteManager::new_with_passwd(&db_str, &None, "mypass");
        assert!(mgr.is_ok());

        cleanup(&path);
    }

    #[test]
    fn test_new_with_passwd_wrong_password_fails() {
        let path = temp_db_path("new_with_pw_bad");
        cleanup(&path);
        let db_str = path.to_str().unwrap().to_string();
        let _mgr = SQLiteManager::new_init_with_passwd(&db_str, &None, "correctpw").unwrap();
        drop(_mgr);

        let result = SQLiteManager::new_with_passwd(&db_str, &None, "badpw");
        assert!(result.is_err());

        cleanup(&path);
    }

    // ── Integration: add + query ─────────────────────────────────────────

    #[test]
    fn test_add_and_query_one() {
        let path = temp_db_path("add_query_one");
        cleanup(&path);
        let db_str = path.to_str().unwrap();
        let mgr = SQLiteManager::new_init_with_passwd(db_str, &None, "pw").unwrap();

        let item = Item {
            site: "github.com".into(),
            account: "user@example.com".into(),
            password: "s3cret!".into(),
        };
        mgr.add(&item).unwrap();

        let found = mgr.query_one("github.com").unwrap();
        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(found.site, "github.com");
        assert_eq!(found.account, "user@example.com");
        assert_eq!(found.password, "s3cret!");

        cleanup(&path);
    }

    #[test]
    fn test_query_one_not_found() {
        let path = temp_db_path("query_one_miss");
        cleanup(&path);
        let db_str = path.to_str().unwrap();
        let mgr = SQLiteManager::new_init_with_passwd(db_str, &None, "pw").unwrap();

        let found = mgr.query_one("nonexistent.com").unwrap();
        assert!(found.is_none());

        cleanup(&path);
    }

    #[test]
    fn test_query_exact_multiple_same_site() {
        let path = temp_db_path("query_multi");
        cleanup(&path);
        let db_str = path.to_str().unwrap();
        let mgr = SQLiteManager::new_init_with_passwd(db_str, &None, "pw").unwrap();

        mgr.add(&Item {
            site: "github.com".into(),
            account: "alice".into(),
            password: "pw1".into(),
        })
        .unwrap();
        mgr.add(&Item {
            site: "github.com".into(),
            account: "bob".into(),
            password: "pw2".into(),
        })
        .unwrap();

        let results = mgr.query("github.com").unwrap().unwrap();
        assert_eq!(results.len(), 2);
        let accounts: Vec<&str> = results.iter().map(|i| i.account.as_str()).collect();
        assert!(accounts.contains(&"alice"));
        assert!(accounts.contains(&"bob"));

        cleanup(&path);
    }

    #[test]
    fn test_query_like_substring_match() {
        let path = temp_db_path("query_like");
        cleanup(&path);
        let db_str = path.to_str().unwrap();
        let mgr = SQLiteManager::new_init_with_passwd(db_str, &None, "pw").unwrap();

        mgr.add(&Item {
            site: "github.com".into(),
            account: "a".into(),
            password: "p".into(),
        })
        .unwrap();
        mgr.add(&Item {
            site: "gitlab.com".into(),
            account: "b".into(),
            password: "p".into(),
        })
        .unwrap();
        mgr.add(&Item {
            site: "stackoverflow.com".into(),
            account: "c".into(),
            password: "p".into(),
        })
        .unwrap();

        // "git" should match github and gitlab
        let results = mgr.query_like("git").unwrap().unwrap();
        assert_eq!(results.len(), 2);
        let sites: Vec<&str> = results.iter().map(|i| i.site.as_str()).collect();
        assert!(sites.contains(&"github.com"));
        assert!(sites.contains(&"gitlab.com"));

        cleanup(&path);
    }

    #[test]
    fn test_query_like_case_insensitive() {
        let path = temp_db_path("query_like_ci");
        cleanup(&path);
        let db_str = path.to_str().unwrap();
        let mgr = SQLiteManager::new_init_with_passwd(db_str, &None, "pw").unwrap();

        mgr.add(&Item {
            site: "GitHub.com".into(),
            account: "a".into(),
            password: "p".into(),
        })
        .unwrap();

        let results = mgr.query_like("github").unwrap().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].site, "GitHub.com");

        cleanup(&path);
    }

    #[test]
    fn test_query_like_percent_returns_all() {
        let path = temp_db_path("query_like_pct");
        cleanup(&path);
        let db_str = path.to_str().unwrap();
        let mgr = SQLiteManager::new_init_with_passwd(db_str, &None, "pw").unwrap();

        mgr.add(&Item {
            site: "a.com".into(),
            account: "a".into(),
            password: "p".into(),
        })
        .unwrap();
        mgr.add(&Item {
            site: "b.com".into(),
            account: "b".into(),
            password: "p".into(),
        })
        .unwrap();

        let results = mgr.query_like("%").unwrap().unwrap();
        assert_eq!(results.len(), 2);

        cleanup(&path);
    }

    #[test]
    fn test_query_like_no_match() {
        let path = temp_db_path("query_like_miss");
        cleanup(&path);
        let db_str = path.to_str().unwrap();
        let mgr = SQLiteManager::new_init_with_passwd(db_str, &None, "pw").unwrap();

        mgr.add(&Item {
            site: "github.com".into(),
            account: "a".into(),
            password: "p".into(),
        })
        .unwrap();

        let results = mgr.query_like("zzz").unwrap().unwrap();
        assert_eq!(results.len(), 0);

        cleanup(&path);
    }

    #[test]
    fn test_query_account_exact() {
        let path = temp_db_path("query_acct");
        cleanup(&path);
        let db_str = path.to_str().unwrap();
        let mgr = SQLiteManager::new_init_with_passwd(db_str, &None, "pw").unwrap();

        mgr.add(&Item {
            site: "a.com".into(),
            account: "alice@example.com".into(),
            password: "p1".into(),
        })
        .unwrap();
        mgr.add(&Item {
            site: "b.com".into(),
            account: "alice@example.com".into(),
            password: "p2".into(),
        })
        .unwrap();
        mgr.add(&Item {
            site: "c.com".into(),
            account: "bob@example.com".into(),
            password: "p3".into(),
        })
        .unwrap();

        let results = mgr.query_account("alice@example.com").unwrap().unwrap();
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|i| i.account == "alice@example.com"));

        cleanup(&path);
    }

    #[test]
    fn test_query_account_like_substring() {
        let path = temp_db_path("query_acct_like");
        cleanup(&path);
        let db_str = path.to_str().unwrap();
        let mgr = SQLiteManager::new_init_with_passwd(db_str, &None, "pw").unwrap();

        mgr.add(&Item {
            site: "a.com".into(),
            account: "alice@example.com".into(),
            password: "p1".into(),
        })
        .unwrap();
        mgr.add(&Item {
            site: "b.com".into(),
            account: "bob@example.com".into(),
            password: "p2".into(),
        })
        .unwrap();

        let results = mgr.query_account_like("example.com").unwrap().unwrap();
        assert_eq!(results.len(), 2);

        let results2 = mgr.query_account_like("alice").unwrap().unwrap();
        assert_eq!(results2.len(), 1);
        assert_eq!(results2[0].account, "alice@example.com");

        cleanup(&path);
    }

    // ── batch_add ────────────────────────────────────────────────────────

    #[test]
    fn test_batch_add() {
        let path = temp_db_path("batch_add");
        cleanup(&path);
        let db_str = path.to_str().unwrap();
        let mgr = SQLiteManager::new_init_with_passwd(db_str, &None, "pw").unwrap();

        let items = vec![
            Item {
                site: "a.com".into(),
                account: "a1".into(),
                password: "p1".into(),
            },
            Item {
                site: "b.com".into(),
                account: "b1".into(),
                password: "p2".into(),
            },
            Item {
                site: "c.com".into(),
                account: "c1".into(),
                password: "p3".into(),
            },
        ];
        mgr.batch_add(&items).unwrap();

        let all = mgr.query_like("%").unwrap().unwrap();
        assert_eq!(all.len(), 3);

        cleanup(&path);
    }

    // ── list_sites ───────────────────────────────────────────────────────

    #[test]
    fn test_list_sites() {
        let path = temp_db_path("list_sites");
        cleanup(&path);
        let db_str = path.to_str().unwrap();
        let mgr = SQLiteManager::new_init_with_passwd(db_str, &None, "pw").unwrap();

        mgr.add(&Item {
            site: "github.com".into(),
            account: "a".into(),
            password: "p".into(),
        })
        .unwrap();
        mgr.add(&Item {
            site: "gitlab.com".into(),
            account: "b".into(),
            password: "p".into(),
        })
        .unwrap();

        let sites = mgr.list_sites().unwrap().unwrap();
        assert_eq!(sites.len(), 2);
        assert!(sites.contains(&"github.com".to_string()));
        assert!(sites.contains(&"gitlab.com".to_string()));

        cleanup(&path);
    }

    // ── Special characters / Unicode ─────────────────────────────────────

    #[test]
    fn test_special_characters_roundtrip() {
        let path = temp_db_path("special_chars");
        cleanup(&path);
        let db_str = path.to_str().unwrap();
        let mgr = SQLiteManager::new_init_with_passwd(db_str, &None, "pw").unwrap();

        let item = Item {
            site: "日本語サイト.jp".into(),
            account: "user+tag@例え.com".into(),
            password: "p@$$w0rd!#%^&*(){}[]|\\:\";<>?,./~`".into(),
        };
        mgr.add(&item).unwrap();

        let found = mgr.query_one("日本語サイト.jp").unwrap().unwrap();
        assert_eq!(found.site, "日本語サイト.jp");
        assert_eq!(found.account, "user+tag@例え.com");
        assert_eq!(found.password, "p@$$w0rd!#%^&*(){}[]|\\:\";<>?,./~`");

        cleanup(&path);
    }

    #[test]
    fn test_emoji_in_fields() {
        let path = temp_db_path("emoji");
        cleanup(&path);
        let db_str = path.to_str().unwrap();
        let mgr = SQLiteManager::new_init_with_passwd(db_str, &None, "pw").unwrap();

        let item = Item {
            site: "🔐vault.com".into(),
            account: "user🎉".into(),
            password: "🔑secret🔑".into(),
        };
        mgr.add(&item).unwrap();

        let found = mgr.query_one("🔐vault.com").unwrap().unwrap();
        assert_eq!(found.password, "🔑secret🔑");

        cleanup(&path);
    }

    // ── Empty database queries ───────────────────────────────────────────

    #[test]
    fn test_empty_db_query_like_returns_empty() {
        let path = temp_db_path("empty_like");
        cleanup(&path);
        let db_str = path.to_str().unwrap();
        let mgr = SQLiteManager::new_init_with_passwd(db_str, &None, "pw").unwrap();

        let results = mgr.query_like("%").unwrap().unwrap();
        assert_eq!(results.len(), 0);

        cleanup(&path);
    }

    #[test]
    fn test_empty_db_query_account_returns_empty() {
        let path = temp_db_path("empty_acct");
        cleanup(&path);
        let db_str = path.to_str().unwrap();
        let mgr = SQLiteManager::new_init_with_passwd(db_str, &None, "pw").unwrap();

        let results = mgr.query_account("anything").unwrap().unwrap();
        assert_eq!(results.len(), 0);

        cleanup(&path);
    }

    // ── Separate key database ────────────────────────────────────────────

    #[test]
    fn test_separate_key_db() {
        let data_path = temp_db_path("sep_data");
        let key_path = temp_db_path("sep_key");
        cleanup(&data_path);
        cleanup(&key_path);

        let data_str = data_path.to_str().unwrap();
        let key_str = key_path.to_str().unwrap();

        let mgr = SQLiteManager::new_init_with_passwd(data_str, &Some(key_str.to_string()), "pw")
            .unwrap();

        mgr.add(&Item {
            site: "test.com".into(),
            account: "user".into(),
            password: "pass".into(),
        })
        .unwrap();

        let found = mgr.query_one("test.com").unwrap().unwrap();
        assert_eq!(found.password, "pass");

        // Re-open with new_with_passwd and separate key db
        drop(mgr);
        let mgr2 =
            SQLiteManager::new_with_passwd(data_str, &Some(key_str.to_string()), "pw").unwrap();
        let found2 = mgr2.query_one("test.com").unwrap().unwrap();
        assert_eq!(found2.password, "pass");

        cleanup(&data_path);
        cleanup(&key_path);
    }

    // ── Persistence: close and reopen ────────────────────────────────────

    #[test]
    fn test_data_persists_across_reopen() {
        let path = temp_db_path("persist");
        cleanup(&path);
        let db_str = path.to_str().unwrap().to_string();

        {
            let mgr = SQLiteManager::new_init_with_passwd(&db_str, &None, "mypw").unwrap();
            mgr.add(&Item {
                site: "persist.com".into(),
                account: "user1".into(),
                password: "p1".into(),
            })
            .unwrap();
            mgr.finish().unwrap();
        }

        // Reopen
        let mgr2 = SQLiteManager::new_with_passwd(&db_str, &None, "mypw").unwrap();
        let found = mgr2.query_one("persist.com").unwrap().unwrap();
        assert_eq!(found.account, "user1");
        assert_eq!(found.password, "p1");

        cleanup(&path);
    }

    // ── HMAC index correctness ───────────────────────────────────────────

    #[test]
    fn test_hmac_index_exact_match_only() {
        let path = temp_db_path("hmac_exact");
        cleanup(&path);
        let db_str = path.to_str().unwrap();
        let mgr = SQLiteManager::new_init_with_passwd(db_str, &None, "pw").unwrap();

        mgr.add(&Item {
            site: "github.com".into(),
            account: "a".into(),
            password: "p".into(),
        })
        .unwrap();
        mgr.add(&Item {
            site: "github.com.evil".into(),
            account: "b".into(),
            password: "p".into(),
        })
        .unwrap();

        // Exact query for "github.com" should only return one item
        let results = mgr.query("github.com").unwrap().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].account, "a");

        cleanup(&path);
    }

    // ── is_v2 / is_legacy detection ──────────────────────────────────────

    #[test]
    fn test_is_v2_on_test_db() {
        let path = temp_db_path("is_v2");
        cleanup(&path);
        let db_str = path.to_str().unwrap();
        let _mgr = SQLiteManager::new_init_with_passwd(db_str, &None, "pw").unwrap();

        let conn = sqlite::open(db_str).unwrap();
        assert!(SQLiteManager::is_v2(&conn));
        assert!(!SQLiteManager::is_legacy(&conn));

        cleanup(&path);
    }

    #[test]
    fn test_is_v2_empty_db() {
        let path = temp_db_path("is_v2_empty");
        cleanup(&path);
        let db_str = path.to_str().unwrap();

        let conn = sqlite::open(db_str).unwrap();
        conn.execute("CREATE TABLE IF NOT EXISTS vanillapm (s TEXT, a BLOB, p BLOB)")
            .unwrap();

        assert!(!SQLiteManager::is_v2(&conn));
        assert!(!SQLiteManager::is_legacy(&conn));

        cleanup(&path);
    }

    // ── Many items stress test ───────────────────────────────────────────

    #[test]
    fn test_many_items() {
        let path = temp_db_path("many_items");
        cleanup(&path);
        let db_str = path.to_str().unwrap();
        let mgr = SQLiteManager::new_init_with_passwd(db_str, &None, "pw").unwrap();

        let count = 50;
        for i in 0..count {
            mgr.add(&Item {
                site: format!("site{}.com", i),
                account: format!("user{}", i),
                password: format!("pass{}", i),
            })
            .unwrap();
        }

        let all = mgr.query_like("%").unwrap().unwrap();
        assert_eq!(all.len(), count);

        // Verify a specific one
        let found = mgr.query_one("site42.com").unwrap().unwrap();
        assert_eq!(found.account, "user42");
        assert_eq!(found.password, "pass42");

        cleanup(&path);
    }
}
