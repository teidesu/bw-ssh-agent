use rusqlite::params;

use crate::constants::DATABASE_PATH;

#[derive(Debug, Clone)]
pub struct IdentityDto {
    pub id: String,
    pub name: String,
    pub public_key: Vec<u8>,
    pub private_key: String,
}

#[derive(Debug)]
pub struct AuthDto {
    pub vault_url: String,
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: i64,
    pub master_key: Vec<u8>,
    pub symmetric_key: Vec<u8>,
}

pub struct Database {
    pub conn: rusqlite::Connection,
}

impl Database {
    pub fn open() -> color_eyre::Result<Self> {
        let conn = rusqlite::Connection::open(&*DATABASE_PATH)?;
        Database::migrate(&conn)?;

        Ok(Self { conn })
    }

    fn migrate(conn: &rusqlite::Connection) -> color_eyre::Result<()> {
        let version: i32 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if version == 0 {
            conn.execute_batch(include_str!("migrations/v1.sql"))?;
            conn.pragma_update(None, "user_version", 1)?;
        }

        Ok(())
    }

    fn map_identity(row: &rusqlite::Row<'_>) -> Result<IdentityDto, rusqlite::Error> {
        let id: String = row.get(0)?;
        let name: String = row.get(1)?;
        let public_key: Vec<u8> = row.get(2)?;
        let private_key: String = row.get(3)?;

        Ok(IdentityDto {
            id,
            name,
            public_key,
            private_key,
        })
    }

    pub fn get_identities(&self) -> color_eyre::Result<Vec<IdentityDto>> {
        let mut stmt = self.conn.prepare_cached("SELECT * FROM identities")?;

        let rows = stmt
            .query_map([], Database::map_identity)?
            .collect::<Vec<_>>();

        Ok(rows.into_iter().flatten().collect())
    }

    fn map_auth(row: &rusqlite::Row<'_>) -> Result<AuthDto, rusqlite::Error> {
        let vault_url: String = row.get(0)?;
        let access_token: String = row.get(1)?;
        let refresh_token: String = row.get(2)?;
        let expires_at: i64 = row.get(3)?;
        let master_key: Vec<u8> = row.get(4)?;
        let symmetric_key: Vec<u8> = row.get(5)?;

        Ok(AuthDto {
            vault_url,
            access_token,
            refresh_token,
            expires_at,
            master_key,
            symmetric_key,
        })
    }

    pub fn add_identity(&self, dto: &IdentityDto) -> color_eyre::Result<()> {
        self.conn.execute(
            "INSERT INTO identities (id, name, public_key, private_key)
                VALUES (?1, ?2, ?3, ?4)
                ON CONFLICT (id) DO UPDATE SET
                    name = excluded.name,
                    public_key = excluded.public_key,
                    private_key = excluded.private_key",
            params![dto.id, dto.name, dto.public_key, dto.private_key],
        )?;

        Ok(())
    }

    pub fn get_identity_by_public_key(
        &self,
        public_key: &[u8],
    ) -> color_eyre::Result<Option<IdentityDto>> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT * FROM identities WHERE public_key = ?1 LIMIT 1")?;

        let rows = stmt
            .query_map([public_key], Database::map_identity)?
            .collect::<Vec<_>>();

        Ok(rows.into_iter().flatten().next())
    }

    pub fn delete_identity(&self, id: &str) -> color_eyre::Result<()> {
        self.conn
            .execute("DELETE FROM identities WHERE id = ?1", params![id])?;

        Ok(())
    }

    pub fn get_auth(&self) -> color_eyre::Result<Option<AuthDto>> {
        let mut stmt = self.conn.prepare_cached("SELECT * FROM auth")?;

        let rows = stmt.query_map([], Database::map_auth)?.collect::<Vec<_>>();

        Ok(rows.into_iter().flatten().next())
    }

    pub fn set_auth(&self, dto: &AuthDto) -> color_eyre::Result<()> {
        // delete any existing auth first
        self.conn.execute("DELETE FROM auth", params![])?;
        self.conn.execute(
            "INSERT INTO auth (vault_url, access_token, refresh_token, expires_at, master_key, symmetric_key) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                dto.vault_url,
                dto.access_token,
                dto.refresh_token,
                dto.expires_at,
                dto.master_key,
                dto.symmetric_key
            ],
        )?;

        Ok(())
    }
}
