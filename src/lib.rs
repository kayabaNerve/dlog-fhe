mod joye_libert;

mod commitment;
pub use commitment::Commitment;

impl Commitment {
  pub fn not(self) -> Self {
    (self * 3) + 1
  }
  pub fn xor(self, other: Commitment) -> Self {
    ((self + other) * 2).half()
  }
  pub fn xnor(self, other: Commitment) -> Self {
    self.xor(other).not()
  }
  pub fn or(self, other: Commitment) -> Self {
    let sum = self + other;
    // ((C + D) - 1) + 2(C + D)
    let part1 = (sum + 3) + (sum * 2);
    // Add NOT XOR
    let part2 = self.xnor(other);
    // Half
    (part1 + part2).half()
  }
  pub fn nor(self, other: Commitment) -> Self {
    self.or(other).not()
  }
}

#[test]
fn test_not() {
  assert_eq!(Commitment::new(0).not(), Commitment::new(1));
  assert_eq!(Commitment::new(1).not(), Commitment::new(0));
}

#[test]
fn test_xor() {
  assert_eq!(Commitment::new(0).xor(Commitment::new(0)), Commitment::new(0));
  assert_eq!(Commitment::new(0).xor(Commitment::new(1)), Commitment::new(1));
  assert_eq!(Commitment::new(1).xor(Commitment::new(0)), Commitment::new(1));
  assert_eq!(Commitment::new(1).xor(Commitment::new(1)), Commitment::new(0));
}

#[test]
fn test_xnor() {
  assert_eq!(Commitment::new(0).xnor(Commitment::new(0)), Commitment::new(1));
  assert_eq!(Commitment::new(0).xnor(Commitment::new(1)), Commitment::new(0));
  assert_eq!(Commitment::new(1).xnor(Commitment::new(0)), Commitment::new(0));
  assert_eq!(Commitment::new(1).xnor(Commitment::new(1)), Commitment::new(1));
}

#[test]
fn test_or() {
  assert_eq!(Commitment::new(0).or(Commitment::new(0)), Commitment::new(0));
  assert_eq!(Commitment::new(0).or(Commitment::new(1)), Commitment::new(1));
  assert_eq!(Commitment::new(1).or(Commitment::new(0)), Commitment::new(1));
  assert_eq!(Commitment::new(1).or(Commitment::new(1)), Commitment::new(1));
}

#[test]
fn test_nor() {
  assert_eq!(Commitment::new(0).nor(Commitment::new(0)), Commitment::new(1));
  assert_eq!(Commitment::new(0).nor(Commitment::new(1)), Commitment::new(0));
  assert_eq!(Commitment::new(1).nor(Commitment::new(0)), Commitment::new(0));
  assert_eq!(Commitment::new(1).nor(Commitment::new(1)), Commitment::new(0));
}
