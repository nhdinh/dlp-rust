use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use dlp_admin_cli::app::{App, Screen};
use dlp_admin_cli::event::AppEvent;
use dlp_admin_cli::screens::handle_event;
use dlp_e2e::helpers;
use tokio::net::TcpListener;

fn setup_test_app() -> (App, std::sync::Arc<dlp_server::db::Pool>, std::net::SocketAddr) {
    let (router, pool) = helpers::server::build_test_app();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("create local runtime");
    let addr = rt.block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind TCP listener");
        let addr = listener.local_addr().expect("get local addr");
        tokio::spawn(async move {
            axum::serve(listener, router).await.expect("mock server serve");
        });
        addr
    });
    let app = helpers::tui::build_test_app_with_mock_client(format!("http://{addr}"));
    (app, pool, addr)
}

fn inject(app: &mut App, key: KeyEvent) {
    handle_event(app, AppEvent::Key(key));
}

fn main() {
    let (mut app, _pool, _addr) = setup_test_app();
    println!("Start screen: {:?}", app.screen);

    let down = KeyEvent::new(KeyCode::Down, KeyModifiers::NONE);
    let enter = KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE);

    for i in 0..3 {
        inject(&mut app, down);
        println!("After Down {}: {:?}", i + 1, app.screen);
    }
    inject(&mut app, enter);
    println!("After Enter: {:?}", app.screen);

    inject(&mut app, down);
    println!("After Down 4: {:?}", app.screen);
    inject(&mut app, enter);
    println!("After Enter 2: {:?}", app.screen);
}
