use crate::framework::Item;

use openssl;
use sqlite;
use std::error::Error;

const SALT_SIZE: usize = 333;

/// Legacy reader for the old v1 database format.
/// Used only during migration to read items from old databases.
pub struct SQLiteLegacyManager {
    connection: sqlite::Connection,
    prikey: openssl::rsa::Rsa<openssl::pkey::Private>,
}

impl SQLiteLegacyManager {
    fn remove_salt(data: &[u8]) -> Vec<u8> {
        if data.len() <= SALT_SIZE {
            return vec![];
        }
        let d = &data[SALT_SIZE..];
        let mut end = d.len() - 1;
        while d[end] == 0 && end >= 1 {
            end -= 1;
        }
        if end == 0 && d[end] == 0 {
            return vec![];
        }
        d[..=end].to_vec()
    }

    /// Open a legacy (v1) database with the given master password.
    /// The v1 format stores the RSA private key encrypted with OpenSSL PEM passphrase
    /// (EVP_BytesToKey / MD5-based KDF) and uses PKCS#1 v1.5 padding for data encryption.
    pub fn new_with_passwd(
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

        let prikey = match kc
            .prepare("SELECT a, p FROM vanillapm WHERE s='vanillapm'")?
            .into_cursor()
            .try_next()?
        {
            Some(values) => openssl::rsa::Rsa::private_key_from_pem_passphrase(
                values[1].as_binary().unwrap(),
                password.as_bytes(),
            )?,
            None => return Err("Not a valid legacy database".into()),
        };

        Ok(SQLiteLegacyManager { connection, prikey })
    }

    /// Read and decrypt all items from the legacy database.
    /// Site names are stored as plaintext TEXT; account and password are RSA-PKCS#1 encrypted BLOBs.
    pub fn read_all(&self) -> Result<Vec<Item>, Box<dyn Error>> {
        let mut items = vec![];
        let mut cursor = self
            .connection
            .prepare("SELECT s, a, p FROM data")?
            .into_cursor();

        while let Some(values) = cursor.try_next()? {
            let site = values[0].as_string().unwrap().to_string();

            let mut dea = vec![0u8; self.prikey.size() as usize];
            self.prikey.private_decrypt(
                values[1].as_binary().unwrap(),
                &mut dea,
                openssl::rsa::Padding::PKCS1,
            )?;
            let account = String::from_utf8(Self::remove_salt(&dea))?;

            let mut dep = vec![0u8; self.prikey.size() as usize];
            self.prikey.private_decrypt(
                values[2].as_binary().unwrap(),
                &mut dep,
                openssl::rsa::Padding::PKCS1,
            )?;
            let password = String::from_utf8(Self::remove_salt(&dep))?;

            items.push(Item {
                site,
                account,
                password,
            });
        }

        Ok(items)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::sqlite::SQLiteManager;
    use crate::framework::{DataManager, Item};
    use rand::RngCore;

    const TEST_RSA_KEY_SIZE: u32 = 4096;

    /// Helper: create a v1 legacy database programmatically at the given path.
    /// Returns the RSA keypair so callers can verify things if needed.
    fn create_v1_db(
        filepath: &str,
        password: &str,
        items: &[Item],
    ) -> Result<openssl::rsa::Rsa<openssl::pkey::Private>, Box<dyn Error>> {
        let connection = sqlite::open(filepath)?;
        connection.execute("CREATE TABLE vanillapm (s TEXT, a BLOB, p BLOB)")?;
        connection.execute("CREATE TABLE data (s TEXT, a BLOB, p BLOB)")?;

        // Generate RSA keypair
        let keypair = openssl::rsa::Rsa::generate(TEST_RSA_KEY_SIZE)?;
        let pubkey_pem = keypair.public_key_to_pem_pkcs1()?;
        let prikey_pem_enc = keypair.private_key_to_pem_passphrase(
            openssl::symm::Cipher::aes_256_cbc(),
            password.as_bytes(),
        )?;

        // Insert the 'vanillapm' marker row with pubkey and encrypted private key
        connection
            .prepare("INSERT INTO vanillapm VALUES ('vanillapm', ?, ?)")?
            .bind(1, pubkey_pem.as_slice())?
            .bind(2, prikey_pem_enc.as_slice())?
            .next()?;

        // Insert data rows: plaintext site, RSA-PKCS1 encrypted (salt || account/password)
        for item in items {
            let mut salt_a = vec![0u8; SALT_SIZE];
            rand::thread_rng().fill_bytes(&mut salt_a);
            salt_a.extend_from_slice(item.account.as_bytes());
            let mut enc_a = vec![0u8; keypair.size() as usize];
            keypair.public_encrypt(&salt_a, &mut enc_a, openssl::rsa::Padding::PKCS1)?;

            let mut salt_p = vec![0u8; SALT_SIZE];
            rand::thread_rng().fill_bytes(&mut salt_p);
            salt_p.extend_from_slice(item.password.as_bytes());
            let mut enc_p = vec![0u8; keypair.size() as usize];
            keypair.public_encrypt(&salt_p, &mut enc_p, openssl::rsa::Padding::PKCS1)?;

            connection
                .prepare("INSERT INTO data VALUES (?, ?, ?)")?
                .bind(1, item.site.as_str())?
                .bind(2, enc_a.as_slice())?
                .bind(3, enc_p.as_slice())?
                .next()?;
        }

        Ok(keypair)
    }

    // ──────────────────── remove_salt tests ────────────────────

    #[test]
    fn test_remove_salt_normal() {
        let mut data = vec![0xABu8; SALT_SIZE];
        data.extend_from_slice(b"hello");
        // Pad with zeros to simulate RSA output buffer
        data.extend_from_slice(&[0u8; 100]);
        let result = SQLiteLegacyManager::remove_salt(&data);
        assert_eq!(result, b"hello");
    }

    #[test]
    fn test_remove_salt_too_short() {
        let data = vec![0u8; SALT_SIZE]; // exactly SALT_SIZE, no payload
        let result = SQLiteLegacyManager::remove_salt(&data);
        assert!(result.is_empty());
    }

    #[test]
    fn test_remove_salt_all_zeros_after_salt() {
        let mut data = vec![0xFFu8; SALT_SIZE];
        data.extend_from_slice(&[0u8; 50]);
        let result = SQLiteLegacyManager::remove_salt(&data);
        assert!(result.is_empty());
    }

    // ──────────────────── Legacy DB read tests ────────────────────

    #[test]
    fn test_create_and_read_legacy_db() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("legacy.db").to_str().unwrap().to_string();

        let test_items = vec![
            Item {
                site: "example.com".into(),
                account: "user@ex.com".into(),
                password: "pass123".into(),
            },
            Item {
                site: "github.com".into(),
                account: "dev".into(),
                password: "gh_token".into(),
            },
        ];

        create_v1_db(&db_path, "oldpassword", &test_items).unwrap();

        // Read back with SQLiteLegacyManager
        let mgr = SQLiteLegacyManager::new_with_passwd(&db_path, &None, "oldpassword").unwrap();
        let items = mgr.read_all().unwrap();

        assert_eq!(items.len(), 2);

        // Items come back in insertion order
        assert_eq!(items[0].site, "example.com");
        assert_eq!(items[0].account, "user@ex.com");
        assert_eq!(items[0].password, "pass123");

        assert_eq!(items[1].site, "github.com");
        assert_eq!(items[1].account, "dev");
        assert_eq!(items[1].password, "gh_token");
    }

    #[test]
    fn test_legacy_wrong_password_fails() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir
            .path()
            .join("legacy_bad.db")
            .to_str()
            .unwrap()
            .to_string();

        let test_items = vec![Item {
            site: "test.com".into(),
            account: "u".into(),
            password: "p".into(),
        }];
        create_v1_db(&db_path, "correct", &test_items).unwrap();

        let result = SQLiteLegacyManager::new_with_passwd(&db_path, &None, "wrong");
        assert!(result.is_err());
    }

    #[test]
    fn test_legacy_empty_db_no_items() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir
            .path()
            .join("legacy_empty.db")
            .to_str()
            .unwrap()
            .to_string();

        create_v1_db(&db_path, "pass", &[]).unwrap();

        let mgr = SQLiteLegacyManager::new_with_passwd(&db_path, &None, "pass").unwrap();
        let items = mgr.read_all().unwrap();
        assert!(items.is_empty());
    }

    #[test]
    fn test_not_a_legacy_db_fails() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("empty.db").to_str().unwrap().to_string();

        // Create a DB without the vanillapm marker row
        let conn = sqlite::open(&db_path).unwrap();
        conn.execute("CREATE TABLE vanillapm (s TEXT, a BLOB, p BLOB)")
            .unwrap();

        let result = SQLiteLegacyManager::new_with_passwd(&db_path, &None, "pass");
        assert!(result.is_err());
    }

    // ──────────────────── Migration roundtrip test ────────────────────

    #[test]
    fn test_migration_v1_to_v2_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let old_path = dir.path().join("old.db").to_str().unwrap().to_string();
        let new_path = dir.path().join("new.db").to_str().unwrap().to_string();

        // Create v1 database with test items
        let test_items = vec![
            Item {
                site: "site1.com".into(),
                account: "alice".into(),
                password: "pw1".into(),
            },
            Item {
                site: "site2.org".into(),
                account: "bob@site2.org".into(),
                password: "pw2!@#".into(),
            },
            Item {
                site: "site3.net".into(),
                account: "charlie".into(),
                password: "complex P@$$w0rd".into(),
            },
        ];
        create_v1_db(&old_path, "oldpass", &test_items).unwrap();

        // Read from old DB
        let old_mgr = SQLiteLegacyManager::new_with_passwd(&old_path, &None, "oldpass").unwrap();
        let old_items = old_mgr.read_all().unwrap();
        assert_eq!(old_items.len(), 3);

        // Write to new v2 DB
        let new_mgr = SQLiteManager::new_init_with_passwd(&new_path, &None, "newpass").unwrap();
        new_mgr.batch_add(&old_items).unwrap();
        new_mgr.finish().unwrap();

        // Reopen v2 DB and verify each item
        let v2_mgr = SQLiteManager::new_with_passwd(&new_path, &None, "newpass").unwrap();

        for expected in &test_items {
            let result = v2_mgr.query_one(&expected.site).unwrap();
            assert!(result.is_some(), "Missing item for site: {}", expected.site);
            let item = result.unwrap();
            assert_eq!(item.site, expected.site);
            assert_eq!(item.account, expected.account);
            assert_eq!(item.password, expected.password);
        }
    }

    #[test]
    fn test_migration_preserves_special_characters() {
        let dir = tempfile::tempdir().unwrap();
        let old_path = dir
            .path()
            .join("special_old.db")
            .to_str()
            .unwrap()
            .to_string();
        let new_path = dir
            .path()
            .join("special_new.db")
            .to_str()
            .unwrap()
            .to_string();

        let test_items = vec![Item {
            site: "unicode-site.com".into(),
            account: "user+tag@email.com".into(),
            password: "p@ss!w0rd#$%^&*()".into(),
        }];
        create_v1_db(&old_path, "pass", &test_items).unwrap();

        let old_mgr = SQLiteLegacyManager::new_with_passwd(&old_path, &None, "pass").unwrap();
        let items = old_mgr.read_all().unwrap();

        let new_mgr = SQLiteManager::new_init_with_passwd(&new_path, &None, "newpass").unwrap();
        new_mgr.batch_add(&items).unwrap();

        let v2_mgr = SQLiteManager::new_with_passwd(&new_path, &None, "newpass").unwrap();
        let result = v2_mgr.query_one("unicode-site.com").unwrap().unwrap();
        assert_eq!(result.account, "user+tag@email.com");
        assert_eq!(result.password, "p@ss!w0rd#$%^&*()");
    }
}
