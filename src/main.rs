use actix_web::{App, HttpServer, web};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::{app_state::AppState, handlers::get_me, middlewares::Auth};

mod app_state;
mod dbs;
mod handlers;
mod middlewares;
mod models;

// Definición de la documentación OpenAPI
#[derive(OpenApi)]
#[openapi(
    paths(
        handlers::create_user,
        handlers::login,
        handlers::get_me
    ),
    components(
        schemas(
            models::User,
            models::CreateUserRequest,
            models::LoginRequest,
            models::LoginResponse,
            models::Claims
        ),

    ),
    tags(
        (name = "web3_project", description = "User Authentication API")
    ),
    security(
        ("bearer_auth" = [])
    ),
    info(
        title = "Project API",
        version = "1.0.0",
        description = "API for user management and authentication."
    )
)]
struct ApiDoc;

#[actix_web::main]
async fn main() {
    let openapi = ApiDoc::openapi();
    match dbs::establish_connection().await {
        Ok(connection) => {
            let created = handlers::create_unique_email_index(&connection).await;
            if created.is_err() {
                println!("Error creating unique email index:");
            }

            println!("Connection established!");

            let app_state = AppState {
                db: connection.clone(),
            };

            match HttpServer::new(move || {
                App::new()
                    .app_data(web::Data::new(app_state.clone()))
                    .service(handlers::create_user)
                    .service(handlers::login)
                    .service(web::scope("/protected").wrap(Auth).service(get_me))
                    .service(
                        SwaggerUi::new("/docs/{_:.*}")
                            .url("/api-docs/openapi.json", openapi.clone()),
                    )
            })
            .bind("127.0.0.1:8080")
            {
                Ok(server) => server.run().await.unwrap(),
                Err(err) => {
                    eprintln!("Error starting server: {:?}", err);
                    std::process::exit(1);
                }
            };
        }
        Err(err) => {
            eprintln!("❌ Failed to connect to the database. Shutting down.");
            eprintln!("   Error details: {}", err);
            std::process::exit(1);
        }
    }
}
