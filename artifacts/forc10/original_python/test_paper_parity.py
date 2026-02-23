from demo1_leaderboard_gaming import run_hysteresis_simulation
from demo4_sybil_attack import run_sybil_simulation


# Experiment 1 (Section 17.3)
def test_hysteresis_stall_exists():
    """Paper Experiment 1: hysteresis must stall at least once."""
    result = run_hysteresis_simulation(
        n_queries=50, delta_sigma=0.005, seed=42
    )
    assert result['stall_count'] > 0, 'Hysteresis produced zero stalls — broken'


# Experiment 1 (Section 17.3)
def test_hysteresis_reduces_leakage():
    """Paper Experiment 1: k-bits with hysteresis must be <= k-bits without."""
    result = run_hysteresis_simulation(
        n_queries=50, delta_sigma=0.005, seed=42
    )
    assert result['k_bits_with'] <= result['k_bits_without'], 'Hysteresis failed to reduce leakage'


# Experiment 11 (Section 17.12)
def test_sybil_naive_succeeds():
    """Paper Experiment 11: naive identity budgeting must allow extraction."""
    result = run_sybil_simulation(
        n_identities=5, topic_budget=2.0, seed=42
    )
    assert result['naive_success'] > 0.5, 'Naive system should allow Sybil extraction'


# Experiment 11 (Section 17.12)
def test_sybil_topichash_collapses():
    """Paper Experiment 11: TopicHash must collapse swarm to near-zero success."""
    result = run_sybil_simulation(
        n_identities=5, topic_budget=2.0, seed=42
    )
    assert result['topichash_success'] < 0.01, 'TopicHash failed to block Sybil attack'


# Experiment 11 (Section 17.12)
def test_sybil_fifth_identity_frozen():
    """Paper Experiment 11: 5th identity must hit FROZEN or REJECT under shared budget."""
    result = run_sybil_simulation(
        n_identities=5, topic_budget=2.0, seed=42
    )
    assert result['fifth_identity_status'] in ('FROZEN', 'REJECT'), (
        f"Expected FROZEN/REJECT, got: {result['fifth_identity_status']}"
    )
