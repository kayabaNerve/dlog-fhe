use core::ops::{Add, Mul};

use rand_core::{RngCore, CryptoRng};

use crate::joye_libert::{PublicKey, Ciphertext};

/// A commitment which can be added to other commitments, scaled, or halved.
///
/// The size of the message space is 4.
///
/// Commitments must be indistinguishable.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Commitment(PublicKey, Ciphertext);
impl Add<u8> for Commitment {
  type Output = Commitment;
  fn add(self, y: u8) -> Self {
    let res = self.0.add_int(self.1, y);
    Commitment(self.0, res)
  }
}
impl Add<Commitment> for Commitment {
  type Output = Commitment;
  fn add(self, y: Self) -> Self {
    let res = self.0.add(self.1, y.1);
    Commitment(self.0, res)
  }
}
impl Mul<u8> for Commitment {
  type Output = Commitment;
  fn mul(self, y: u8) -> Self {
    let res = self.0.mul(self.1, y);
    Commitment(self.0, res)
  }
}

impl Commitment {
  pub fn new<R: RngCore + CryptoRng>(rng: &mut R, public_key: PublicKey, bit: u8) -> Self {
    assert_eq!(bit | 1, 1);
    let commitment = public_key.encrypt(rng, bit);
    Commitment(public_key, commitment)
  }

  pub fn half(self) -> Self {
    let half = self.0.half(self.1);
    Commitment(self.0, half)
  }

  pub fn unwrap(self) -> Ciphertext {
    self.1
  }
}
