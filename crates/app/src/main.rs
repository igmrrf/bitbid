use yew::Renderer;

mod app;
mod ethereum;
mod rpc;

fn main() {
    console_error_panic_hook::set_once();
    Renderer::<app::App>::new().render();
}
