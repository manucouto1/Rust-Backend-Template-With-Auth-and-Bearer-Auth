use crate::app_state::AppState;
use crate::models::{Claims, CreateUserRequest, LoginRequest, LoginResponse, User};
use actix_web::{HttpMessage, HttpRequest, HttpResponse, Responder, get, post, web};
use bcrypt::{DEFAULT_COST, hash, verify};
use chrono::Utc;
use jsonwebtoken::{EncodingKey, Header, encode};
use mongodb::bson::doc;
use mongodb::options::IndexOptions;
use mongodb::results::CreateIndexResult;
use mongodb::{Database, IndexModel};
use std::time::{SystemTime, UNIX_EPOCH};

pub async fn create_unique_email_index(
    db: &Database,
) -> Result<CreateIndexResult, mongodb::error::Error> {
    let options = IndexOptions::builder().unique(true).build();
    let index = IndexModel::builder()
        .keys(doc! {"email" : 1})
        .options(options)
        .build();

    db.collection::<User>("users").create_index(index).await
}

#[utoipa::path(
    post,
    path = "/register",
    request_body = CreateUserRequest,
    responses(
        (status = 201, description = "User created successfully", body = User),
        (status = 409, description = "User with this email already exists"),
        (status = 500, description = "Internal server error")
    )
)]
#[post("/register")]
pub async fn create_user(
    state: web::Data<AppState>,
    user_req: web::Json<CreateUserRequest>,
) -> impl Responder {
    let password_hash = match hash(&user_req.password, DEFAULT_COST) {
        Ok(hash) => hash,
        Err(e) => return HttpResponse::InternalServerError().json(e.to_string()),
    };
    let now_time = Utc::now();
    let new_user = User {
        id: None,
        username: user_req.username.clone(),
        email: user_req.email.clone(),
        password_hash: password_hash.clone(),
        created_at: now_time.clone(),
    };

    let collection = state.db.collection::<User>("users");

    match collection.insert_one(new_user).await {
        Ok(result) => {
            let created_user = User {
                id: result.inserted_id.as_object_id(),
                username: user_req.username.clone(),
                email: user_req.email.clone(),
                password_hash: password_hash.clone(),
                created_at: now_time.clone(),
            };
            HttpResponse::Created().json(created_user)
        }
        Err(e) => {
            // Handle duplicate key error specifically
            if e.to_string().contains("E11000 duplicate key error") {
                return HttpResponse::Conflict().json("User with this email already exists.");
            }
            HttpResponse::InternalServerError().json(e.to_string())
        }
    }
}

#[utoipa::path(
    post,
    path = "/login",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login successful", body = LoginResponse),
        (status = 401, description = "Invalid credentials"),
        (status = 500, description = "Internal server error")
    )
)]
#[post("/login")]
pub async fn login(
    state: web::Data<AppState>,
    login_req: web::Json<LoginRequest>,
) -> impl Responder {
    let collection = state.db.collection::<User>("users");
    let email = login_req.email.clone().to_lowercase();

    match collection.find_one(doc! {"email": email}).await {
        Ok(Some(user)) => {
            if verify(&login_req.password, &user.password_hash).unwrap() {
                let secret = std::env::var("SECRET_KEY").expect("SECRET_KEY not found");
                let exp = (SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    + 3600) as usize; // Expira en 1 hora
                let claims = Claims {
                    sub: user.email,
                    exp,
                };
                let token = match encode(
                    &Header::default(),
                    &claims,
                    &EncodingKey::from_secret(secret.as_ref()),
                ) {
                    Ok(token) => token,
                    Err(_) => {
                        return HttpResponse::InternalServerError().body("Error generating token");
                    }
                };

                HttpResponse::Ok().json(LoginResponse {
                    access_token: token,
                })
            } else {
                HttpResponse::Unauthorized().body("Invalid credentials")
            }
        }
        Ok(None) => HttpResponse::NotFound().body("User not found"),
        Err(e) => {
            eprintln!("Database error: {:?}", e); // Imprime el error en la consola
            HttpResponse::InternalServerError().body("An internal error occurred.")
        }
    }
}

#[utoipa::path(
    get,
    path = "/me",
    responses(
        (status = 200, description = "Current user data", body = User),
        (status = 401, description = "Unauthorized, token is missing or invalid"),
        (status = 404, description = "User from token not found")
    ),
    security(
        ("bearer_auth" = [])
    )
)]
#[get("/me")]
pub async fn get_me(req: HttpRequest, state: web::Data<AppState>) -> impl Responder {
    // <-- CAMBIA 'db' por 'state'
    if let Some(claims) = req.extensions().get::<Claims>() {
        let collection = state.db.collection::<User>("users"); // <-- USA state.db
        match collection.find_one(doc! { "email": &claims.sub }).await {
            Ok(Some(user)) => HttpResponse::Ok().json(user),
            _ => HttpResponse::NotFound().body("User from token not found"),
        }
    } else {
        HttpResponse::Unauthorized().body("No valid token provided")
    }
}
