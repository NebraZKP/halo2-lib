#![cfg_attr(feature = "strict", deny(warnings))]
#![feature(trait_alias)]

pub mod circuit;
pub mod native;
pub mod recursion;

#[cfg(test)]
mod tests;
