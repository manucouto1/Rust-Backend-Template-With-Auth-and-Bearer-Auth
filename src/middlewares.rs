use crate::models::Claims;
use actix_web::{
    Error, HttpMessage,
    body::EitherBody,
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
};
use futures::future::{LocalBoxFuture, Ready, ready};
use jsonwebtoken::{DecodingKey, Validation, decode};
use std::env;

pub struct Auth;

impl<S, B> Transform<S, ServiceRequest> for Auth
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static + actix_web::body::MessageBody, // <--- AÑADE ESTA RESTRICCIÓN
{
    type Response = ServiceResponse<EitherBody<B>>; // <--- CAMBIA ESTO
    type Error = Error;
    type InitError = ();
    type Transform = AuthMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthMiddleware { service }))
    }
}

pub struct AuthMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for AuthMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static + actix_web::body::MessageBody,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(
        &self,
        ctx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Result<(), Self::Error>> {
        self.service.poll_ready(ctx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        // 1. Extraer el token de la cabecera "Authorization".
        let token = match req.headers().get("Authorization") {
            Some(value) => {
                let parts: Vec<&str> = value.to_str().unwrap_or("").split_whitespace().collect();
                if parts.len() == 2 && parts[0] == "Bearer" {
                    Some(parts[1].to_string())
                } else {
                    None
                }
            }
            None => None,
        };

        if let Some(token) = token {
            let secret = env::var("SECRET_KEY").expect("SECRET_KEY must be set");
            let decoding_key = DecodingKey::from_secret(secret.as_ref());
            let validation = Validation::default();

            // 2. Validar el token (firma y expiración).
            match decode::<Claims>(&token, &decoding_key, &validation) {
                Ok(token_data) => {
                    // 3. Si es válido, adjuntar los claims a la petición.
                    req.extensions_mut().insert(token_data.claims);
                }
                Err(_) => {
                    // Si el token es inválido, devolvemos un error Unauthorized.
                    // La petición no continuará hacia el handler.

                    let res = req
                        .into_response(actix_web::HttpResponse::Unauthorized().finish())
                        .map_into_right_body(); // <--- CAMBIA ESTO

                    return Box::pin(async { Ok(res) });
                }
            }
        } else {
            let res = req
                .into_response(actix_web::HttpResponse::Unauthorized().finish())
                .map_into_right_body(); // <--- CAMBIA ESTO
            return Box::pin(async move { Ok(res) });
        }

        // 4. Si todo fue bien, pasar la petición al siguiente servicio (o al handler).
        let fut = self.service.call(req);
        Box::pin(async move {
            let res = fut.await?;
            Ok(res.map_into_left_body())
        })
    }
}
