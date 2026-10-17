//! Rust port of henrypp/simplewall (GPL-3.0).
//! The C sources live in `D:\Coding\simplewall-master`. This crate keeps the
//! WFP provider, the internal rule list, the rule syntax, and the command line.

mod apps;
mod cli;
mod log;
mod model;
mod profile;
mod rules;
mod ui;
mod wfp;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if !args.is_empty() {
        let code = cli::run(&args);
        std::process::exit(code);
    }
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([1100.0, 720.0])
            .with_title("simplewall"),
        ..Default::default()
    };
    if let Err(err) = eframe::run_native(
        "simplewall",
        options,
        Box::new(|cc| Ok(Box::new(ui::SimplewallApp::new(cc)))),
    ) {
        eprintln!("{err}");
        std::process::exit(1);
    }
}
