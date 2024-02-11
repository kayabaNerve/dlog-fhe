use core::ops::{Add, Mul};

/// A commitment which can be added to other commitments, scaled, or halved.
///
/// The size of the message space is 4.
///
/// Commitments for 0 or 1 must be indistinguishable.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Commitment(u8);
impl Add<u8> for Commitment {
  type Output = Commitment;
  fn add(self, y: u8) -> Self {
     Commitment((self.0 + y) % 4)
  }
}
impl Add<Commitment> for Commitment {
  type Output = Commitment;
  fn add(self, y: Self) -> Self {
    Commitment((self.0 + y.0) % 4)
  }
}
impl Mul<u8> for Commitment {
  type Output = Commitment;
  fn mul(self, y: u8) -> Self {
    Commitment((self.0 * y) % 4)
  }
}

impl Commitment {
  pub fn new(bit: u8) -> Self {
    assert_eq!(bit | 1, 1);
    Commitment(bit)
  }

  pub fn half(self) -> Self {
    assert_eq!(self.0 % 2, 0);
    Commitment(self.0 / 2)
  }
}
