use super::engine::Engine;

// Consensus handlese the full state replication process which includes the coordination of
// sending and receiving PBFT messages.
pub struct Consensus {
    engine: Engine,
}
