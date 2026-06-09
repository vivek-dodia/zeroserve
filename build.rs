fn main() {
    // Generate the Caddyfile block-interior parser from the lalrpop grammar.
    // We use an external lexer (our own tokenizer), so lalrpop's built-in
    // lexer is disabled; it only generates the LR(1) tables.
    lalrpop::process_src().expect("lalrpop grammar generation failed");
    println!("cargo:rerun-if-changed=src/caddyfile/grammar.lalrpop");
}
