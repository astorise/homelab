use rand::{distributions::Alphanumeric, Rng};

pub(crate) fn generate_password(length: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
  }
  
