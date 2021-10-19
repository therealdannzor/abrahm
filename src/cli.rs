use clap::{App, Arg};

pub fn read_args() -> u32 {
    let matches = App::new("AbrahmChain")
        .arg(
            Arg::with_name("node")
                .takes_value(true)
                .required(true)
                .short("n")
                .long("node"),
        )
        .get_matches();

    matches
        .value_of("node")
        .unwrap()
        .to_string()
        .parse::<u32>()
        .unwrap()
}
