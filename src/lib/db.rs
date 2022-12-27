use postgres::{Client, NoTls};
use anyhow::Result;

pub struct DB {
    pub client: Client,
}

impl DB {
    pub fn new(params: &str) -> Self {
        let client = Client::connect(params, NoTls).unwrap();
        return DB { client };
    }

    /* 
     * Begin authentication methods
     */
    pub fn add_api_key(&mut self, host: &str, api_key: &str) -> Result<()> {
        let q = "INSERT INTO loc_auth (host, api_key) VALUES ($1, $2)";

        self.client.execute(q, &[&host, &api_key])?;

        return Ok(());
    }

    pub fn api_key_exists(&mut self, api_key: &str) -> bool {
        let q = "SELECT host FROM loc_auth WHERE api_key = $1";

        if let Ok(_) = self.client.query_one(q, &[&api_key]) {
            return true;
        }
        
        return false;
    }

    pub fn get_host_for_api_key(&mut self, api_key: &str) -> Result<String> {
        let q = "SELECT host FROM loc_auth WHERE api_key = $1";

        let row = self.client.query_one(q, &[&api_key])?;

        let ret: String = row.get("host");

        return Ok(ret);
    }

    /*
     * Begin secret methods
     */
    pub fn create_secret(&mut self, ident: &str, secret: &str) -> Result<()> {
        let q = "INSERT INTO secrets (ident, token) VALUES ($1, $2)";

        self.client.execute(q, &[&ident, &secret])?;

        return Ok(());
    }

    pub fn delete_secret(&mut self, ident: &str) -> Result<()> {
        let q = "DELETE FROM secrets WHERE ident = $1";

        self.client.execute(q, &[&ident])?;

        return Ok(());
    }

    pub fn get_secret(&mut self, ident: &str) -> Result<(i64, String)> {
        let q = "SELECT id, token FROM secrets WHERE ident = $1";

        let row = self.client.query_one(q, &[&ident])?;
        let token: String = row.get("token");
        let id: i64 = row.get("id");

        return Ok((id, token));
    }

    #[allow(dead_code)]
    pub fn get_secret_by_id(&mut self, id: i64) -> Result<(String, String)> {
        let q = "SELECT ident, token FROM secrets WHERE id = $1";

        let row = self.client.query_one(q, &[&id])?;
        let token: String = row.get("token");
        let ident: String = row.get("ident");

        return Ok((ident, token));
    }
}

/*
 * Unit tests
 */
fn _test_setup() -> DB {
    let params = "host=fserver.splitstreams.com \
        port=5432 \
        user=test \
        password=c_3ZKNpDAq272CPR5FOx2jOb72C1I-lV \
        dbname=testing \
        sslmode=prefer";
    let conn = DB::new(params);

    return conn;
}

fn _test_cleanup(conn: &mut DB) {
    conn.client.execute("DELETE FROM secrets", &[]).unwrap();
    conn.client.execute("DELETE FROM loc_auth", &[]).unwrap();
}

#[test]
fn test_connection() {
    let mut conn = _test_setup();
    _test_cleanup(&mut conn);
}

#[test]
fn test_secrets() {
    let mut conn = _test_setup();

    let ident = "test_ident";
    let secret = "abc123";

    let res = conn.create_secret(ident, secret);
    if let Err(e) = res {
        panic!("Error: {}", e);
    }
    assert!(res.is_ok());

    let (id, token) = conn.get_secret(ident).unwrap();
    assert_eq!(token, secret);

    let (ret_ident, ret_token) = conn.get_secret_by_id(id).unwrap();
    assert_eq!(ret_ident, ident);
    assert_eq!(ret_token, secret);

    let res = conn.delete_secret(ident);

    assert!(res.is_ok());

    let res = conn.get_secret(ident);

    assert!(res.is_err());

    _test_cleanup(&mut conn);
}

#[test]
fn test_api_key() {
    let mut conn = _test_setup();
    let host = "test.example.com";
    let api_key = "abc12345";

    let res = conn.add_api_key(host, api_key);
    assert!(res.is_ok());

    assert!(conn.api_key_exists(api_key));

    let res = conn.get_host_for_api_key(api_key);

    assert!(res.is_ok());
    assert_eq!(res.unwrap(), host.to_string());

    _test_cleanup(&mut conn);
}