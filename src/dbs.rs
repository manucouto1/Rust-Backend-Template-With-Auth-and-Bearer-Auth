use dotenv::dotenv;
use mongodb::{Client, Database, bson::doc};
use std::env;

pub async fn establish_connection() -> Result<Database, mongodb::error::Error> {
    dotenv().ok();
    let uri = env::var("MONGO_URI").expect("Missing MONGODB_URI environment variable");
    let db_name = env::var("DB_NAME").expect("Missing DB_NAME environment variable");
    let client = Client::with_uri_str(&uri).await;
    match client {
        Ok(client) => {
            return match client.database("admin").run_command(doc! {"ping": 1}).await {
                Ok(_) => Ok(client.database(&db_name)),
                Err(err) => Err(err),
            };
        }
        Err(err) => return Err(err),
    }
}
