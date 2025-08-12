#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Service {
    Dns,
    Https,
    K3s,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ServiceState {
    Running,  // OK
    Warning,  // intermédiaire
    Stopped,  // Down
    Error,    // Down aussi (on mappe sur la même couleur que Stopped)
}
