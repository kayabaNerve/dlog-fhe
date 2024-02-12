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
    let sum = self.clone() + other.clone();
    // ((C + D) - 1) + 2(C + D)
    let part1 = (sum.clone() + 3) + (sum * 2);
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
  let (private, public) = joye_libert::PrivateKey::new(&mut rand_core::OsRng);
  assert_eq!(
    private.decrypt(Commitment::new(&mut rand_core::OsRng, public.clone(), 0).not().unwrap()),
    Some(1)
  );
  assert_eq!(
    private.decrypt(Commitment::new(&mut rand_core::OsRng, public, 1).not().unwrap()),
    Some(0)
  );
}

#[test]
fn test_xor() {
  let (private, public) = joye_libert::PrivateKey::new(&mut rand_core::OsRng);
  assert_eq!(
    private.decrypt(
      Commitment::new(&mut rand_core::OsRng, public.clone(), 0)
        .xor(Commitment::new(&mut rand_core::OsRng, public.clone(), 0))
        .unwrap()
    ),
    Some(0)
  );
  assert_eq!(
    private.decrypt(
      Commitment::new(&mut rand_core::OsRng, public.clone(), 0)
        .xor(Commitment::new(&mut rand_core::OsRng, public.clone(), 1))
        .unwrap()
    ),
    Some(1)
  );
  assert_eq!(
    private.decrypt(
      Commitment::new(&mut rand_core::OsRng, public.clone(), 1)
        .xor(Commitment::new(&mut rand_core::OsRng, public.clone(), 0))
        .unwrap()
    ),
    Some(1)
  );
  assert_eq!(
    private.decrypt(
      Commitment::new(&mut rand_core::OsRng, public.clone(), 1)
        .xor(Commitment::new(&mut rand_core::OsRng, public, 1))
        .unwrap()
    ),
    Some(0)
  );
}

#[test]
fn test_xnor() {
  let (private, public) = joye_libert::PrivateKey::new(&mut rand_core::OsRng);
  assert_eq!(
    private.decrypt(
      Commitment::new(&mut rand_core::OsRng, public.clone(), 0)
        .xnor(Commitment::new(&mut rand_core::OsRng, public.clone(), 0))
        .unwrap()
    ),
    Some(1)
  );
  assert_eq!(
    private.decrypt(
      Commitment::new(&mut rand_core::OsRng, public.clone(), 0)
        .xnor(Commitment::new(&mut rand_core::OsRng, public.clone(), 1))
        .unwrap()
    ),
    Some(0)
  );
  assert_eq!(
    private.decrypt(
      Commitment::new(&mut rand_core::OsRng, public.clone(), 1)
        .xnor(Commitment::new(&mut rand_core::OsRng, public.clone(), 0))
        .unwrap()
    ),
    Some(0)
  );
  assert_eq!(
    private.decrypt(
      Commitment::new(&mut rand_core::OsRng, public.clone(), 1)
        .xnor(Commitment::new(&mut rand_core::OsRng, public, 1))
        .unwrap()
    ),
    Some(1)
  );
}

#[test]
fn test_or() {
  let (private, public) = joye_libert::PrivateKey::new(&mut rand_core::OsRng);
  assert_eq!(
    private.decrypt(
      Commitment::new(&mut rand_core::OsRng, public.clone(), 0)
        .or(Commitment::new(&mut rand_core::OsRng, public.clone(), 0))
        .unwrap()
    ),
    Some(0)
  );
  assert_eq!(
    private.decrypt(
      Commitment::new(&mut rand_core::OsRng, public.clone(), 0)
        .or(Commitment::new(&mut rand_core::OsRng, public.clone(), 1))
        .unwrap()
    ),
    Some(1)
  );
  assert_eq!(
    private.decrypt(
      Commitment::new(&mut rand_core::OsRng, public.clone(), 1)
        .or(Commitment::new(&mut rand_core::OsRng, public.clone(), 0))
        .unwrap()
    ),
    Some(1)
  );
  assert_eq!(
    private.decrypt(
      Commitment::new(&mut rand_core::OsRng, public.clone(), 1)
        .or(Commitment::new(&mut rand_core::OsRng, public, 1))
        .unwrap()
    ),
    Some(1)
  );
}

#[test]
fn test_nor() {
  let (private, public) = joye_libert::PrivateKey::new(&mut rand_core::OsRng);
  assert_eq!(
    private.decrypt(
      Commitment::new(&mut rand_core::OsRng, public.clone(), 0)
        .nor(Commitment::new(&mut rand_core::OsRng, public.clone(), 0))
        .unwrap()
    ),
    Some(1)
  );
  assert_eq!(
    private.decrypt(
      Commitment::new(&mut rand_core::OsRng, public.clone(), 0)
        .nor(Commitment::new(&mut rand_core::OsRng, public.clone(), 1))
        .unwrap()
    ),
    Some(0)
  );
  assert_eq!(
    private.decrypt(
      Commitment::new(&mut rand_core::OsRng, public.clone(), 1)
        .nor(Commitment::new(&mut rand_core::OsRng, public.clone(), 0))
        .unwrap()
    ),
    Some(0)
  );
  assert_eq!(
    private.decrypt(
      Commitment::new(&mut rand_core::OsRng, public.clone(), 1)
        .nor(Commitment::new(&mut rand_core::OsRng, public, 1))
        .unwrap()
    ),
    Some(0)
  );
}
