mod routes;

use actix_cors::Cors;
use actix_web::middleware::Logger;
use actix_web::{App, HttpServer, web};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    println!("  ╔══════════════════════════════════╗");
    println!("  ║       devastator v0.1.0          ║");
    println!("  ║  Hash & Cipher Toolkit           ║");
    println!("  ╚══════════════════════════════════╝");
    println!("  Listening on http://127.0.0.1:8080");

    let frontend_path = std::env::current_dir()
        .map(|p| p.join("frontend"))
        .unwrap_or_else(|_| std::path::PathBuf::from("frontend"));

    HttpServer::new(move || {
        let cors = Cors::permissive();

        App::new()
            .wrap(cors)
            .wrap(Logger::default())
            .service(
                web::scope("/api")
                    .route("/hash/identify", web::post().to(routes::hash_identify))
                    .route("/hash/crack", web::post().to(routes::hash_crack))
                    .route("/hash/bruteforce", web::post().to(routes::hash_bruteforce))
                    .route("/cipher/detect", web::post().to(routes::cipher_detect))
                    .route("/cipher/decode", web::post().to(routes::cipher_decode))
                    .route("/cipher/encode", web::post().to(routes::cipher_encode)),
            )
            .route("/health", web::get().to(routes::health))
            .service(actix_files::Files::new("/", frontend_path.clone()).index_file("index.html"))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
