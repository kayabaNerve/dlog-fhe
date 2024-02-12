use core::cmp::Ordering;

use rand_core::{RngCore, CryptoRng};

use crypto_bigint::{Encoding, Uint};
use crypto_primes::generate_prime_with_rng;

use malachite::{
  num::{basic::traits::*, arithmetic::traits::*, logic::traits::*, conversion::traits::*},
  *,
};

#[cfg(test)]
const RHO_BITS: usize = 1024;
#[cfg(not(test))]
const RHO_BITS: usize = 3072;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PublicKey {
  g: Natural,
  N: Natural,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PrivateKey {
  p: Natural,
  u: Natural,
  public_key: PublicKey,
}

struct Ciphertext(Natural);

impl PrivateKey {
  pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> (PrivateKey, PublicKey) {
    debug_assert_eq!(Uint::<{ RHO_BITS / 64 }>::BITS, RHO_BITS);

    let p = loop {
      let p = generate_prime_with_rng::<{ RHO_BITS / 64 }>(&mut *rng, None);
      let p =
        Natural::from_digits_desc(&256u16, p.to_be_bytes().as_ref().iter().map(|b| (*b).into()))
          .unwrap();

      if (&p % Natural::from(2u8.pow(2))) == 1 {
        break p;
      }
    };

    let q = loop {
      let q = generate_prime_with_rng::<{ RHO_BITS / 64 }>(&mut *rng, None);
      let q =
        Natural::from_digits_desc(&256u16, q.to_be_bytes().as_ref().iter().map(|b| (*b).into()))
          .unwrap();

      if (&q % Natural::from(4u8)) == 3 {
        break q;
      }
    };

    let g = loop {
      let mut g_bytes = [0; RHO_BITS / 8];
      rng.fill_bytes(&mut g_bytes);
      let g =
        Natural::from_digits_desc(&256u16, g_bytes.as_ref().iter().map(|b| (*b).into())).unwrap();
      if (g != 0) &&
        (g < p) &&
        (g < q) &&
        (g.clone().legendre_symbol(&p) == -1) &&
        (g.clone().legendre_symbol(&q) == -1)
      {
        break g;
      }
    };

    let N = &p * &q;

    let p_apostrophe = (&p - Natural::ONE) / Natural::from(2u8.pow(2));

    let public_key = PublicKey { g, N };
    (PrivateKey { p, u: p_apostrophe, public_key: public_key.clone() }, public_key)
  }

  pub fn decrypt(&self, ciphertext: Ciphertext) -> Option<u8> {
    let p_sub_1_div = (self.p.clone() - Natural::ONE) / Natural::from(2u8.pow(2));

    let z = (ciphertext.0 % &self.p).mod_pow(&p_sub_1_div, &self.p);
    if z == Natural::ONE {
      return Some(0);
    }

    let base = self.public_key.g.clone().mod_pow(p_sub_1_div, &self.p);
    if z == base {
      return Some(1);
    }

    if z == base.clone().mod_pow(Natural::from(2u8), &self.p) {
      return Some(2);
    }

    if z == base.mod_pow(Natural::from(3u8), &self.p) {
      return Some(3);
    }

    None

    /*
    For some reason, the below is a *not working* fast decrypt.

    let inv = p_sub_1_div.clone().mod_pow(self.p.clone() - Natural::from(2u8), &self.p);
    assert_eq!((&inv * &p_sub_1_div) % &self.p, Natural::ONE);
    let D = (self.public_key.g.clone() * inv) % &self.p;
    let mut m = 0;
    let mut B = 1;
    let mut C = (ciphertext.0 % &self.p).mod_pow(p_sub_1_div, &self.p);

    let j = 1;
    let z = (&C * &C) % &self.p;
    if z != Natural::ONE {
      m += B;
      C = (C * D.clone()) % &self.p;
    }
    B *= 2;

    if C != Natural::ONE {
      m += B;
    }
    Some(m)
    */
  }
}

impl PublicKey {
  pub fn encrypt<R: RngCore + CryptoRng>(&self, rng: &mut R, message: u8) -> (Natural, Ciphertext) {
    assert!(message < 4);

    let x = loop {
      let mut x_bytes = [0; (RHO_BITS * 2) / 8];
      rng.fill_bytes(&mut x_bytes);
      let x =
        Natural::from_digits_desc(&256u16, x_bytes.as_ref().iter().map(|b| (*b).into())).unwrap();
      if (x != 0) && (x < self.N) {
        break x;
      }
    };

    // TODO: Check the security of using pow(8)
    (
      x.clone(),
      Ciphertext(
        (self.g.clone().mod_pow(&Natural::from(message), &self.N) *
          x.mod_pow(&Natural::from(2u8.pow(8)), &self.N)) %
          &self.N,
      ),
    )

    // Jacobi C / N checks its validity
  }
}

#[test]
fn test_joye_libert() {
  use rand_core::OsRng;
  let (private, public) = PrivateKey::new(&mut OsRng);
  assert_eq!(private.decrypt(public.encrypt(&mut OsRng, 0).1), Some(0));
  assert_eq!(private.decrypt(public.encrypt(&mut OsRng, 1).1), Some(1));
  assert_eq!(private.decrypt(public.encrypt(&mut OsRng, 2).1), Some(2));
  assert_eq!(private.decrypt(public.encrypt(&mut OsRng, 3).1), Some(3));
}

#[test]
fn test_homomorphic() {
  use rand_core::OsRng;
  let (private, public) = PrivateKey::new(&mut OsRng);
  for c1 in 0 .. 4 {
    let cipher1 = public.encrypt(&mut OsRng, c1).1;
    for c2 in 0 .. 4 {
      let cipher2 = public.encrypt(&mut OsRng, c2).1;
      // Addition via multiplying ciphertexts
      assert_eq!(
        private.decrypt(Ciphertext((&cipher1.0 * cipher2.0) % &public.N)),
        Some((c1 + c2) % 4)
      );
      // Multiplication by a scalar via pow
      assert_eq!(
        private.decrypt(Ciphertext(cipher1.0.clone().mod_pow(Natural::from(c2), &public.N))),
        Some((c1 * c2) % 4)
      );
    }
  }
}

fn inverse(a: &Integer, n: &Integer) -> Natural {
  let mut t = Integer::ZERO;
  let mut r = n.clone();
  let mut newt = Integer::ONE;
  let mut newr = a.clone();

  while newr != Integer::ZERO {
    let quotient = &r / &newr;
    (t, newt) = (newt.clone(), t - (&quotient * newt));
    (r, newr) = (newr.clone(), r - (quotient * newr));
  }

  if r > Integer::ONE {
    panic!("no inverse");
  }
  if t < Integer::ZERO {
    t += n;
  }

  t.unsigned_abs()
}

#[test]
fn test_halving() {
  use rand_core::OsRng;
  for i in 0 .. 128 {
    dbg!(i);

    let (private, public) = PrivateKey::new(&mut OsRng);

    // 1       -> 1
    // g ** 2  -> g
    //
    // We introduce a new factor to the ciphertext to accomplish this.
    //
    // (1    * x) - (x - 1) = 1 for any x
    // (g**2 * x) - (x - 1) = g**1
    // Solve for x
    //
    // (g * g * x) - (x - 1) = g
    // (g * g * x) + x + 1 = g
    // (g * g * x) + x = g - 1
    // (g * g) + 1 = (g - 1)/x

    // (g * g * x) = g + (x - 1)
    // g * g = (g + (x - 1))/x
    // g * g = g/x + (1 - (1/x))
    // g * g - (1 - 1/x) = g/x
    // g * g + -1 + 1/x = g/x
    // g * g + -1 = g/x - 1/x
    // g * g + -1 = (g-1)/x

    let lhs = (&public.g * &public.g) - Natural::ONE;
    let rhs_numerator = &public.g - Natural::ONE;

    // (g * g + -1) / (g - 1) = 1/x
    let denominator = rhs_numerator;
    let inv_denom = inverse(&Integer::from(denominator), &Integer::from(public.N.clone()));
    let x = lhs * inv_denom;
    // 1/x -> x
    let x = inverse(&Integer::from(x), &Integer::from(public.N.clone()));

    assert_eq!((Natural::ONE * &x) - (&x - Natural::ONE), Natural::ONE);
    assert_eq!(
      ((public.g.clone().mod_pow(Natural::from(2u8), &public.N) * &x) - (&x - Natural::ONE)) %
        &public.N,
      public.g
    );

    let transform = |ciphertext: Ciphertext| {
      let lhs = (ciphertext.0 * &x) % &public.N;
      let rhs = &x - Natural::ONE;
      let res = (if lhs > rhs { lhs - rhs } else { lhs + (&public.N - rhs) }) % &public.N;
      Ciphertext(res)
    };

    assert_eq!(private.decrypt(transform(public.encrypt(&mut OsRng, 0).1)), Some(0));
    assert_eq!(private.decrypt(transform(public.encrypt(&mut OsRng, 2).1)), Some(1));

    let already_halved = transform(public.encrypt(&mut OsRng, 2).1);
    // Scale back to 2
    let back = Ciphertext(already_halved.0.clone().mod_pow(Natural::from(2u8), &public.N));
    // Check this still works
    assert_eq!(private.decrypt(transform(back)), Some(1));
  }
}
