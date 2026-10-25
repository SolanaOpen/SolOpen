// Reconstructed source for <PROGRAM_ID>.
//
// Rules that keep the bytes reproducible:
//  - Panic locations (file:line:column) are compiled into the binary. Keep the
//    file layout from `solopen.py inspect` (programs/<x>/src/...), and never
//    run rustfmt over a file once a function in it matches.
//  - Write one instruction at a time. After each change run `solopen.py try`
//    and watch that instruction's handler functions leave the "don't match
//    yet" list.
//  - The program id below must be the original's (it is embedded).
use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

#[program]
pub mod my_program {
    use super::*;
}
