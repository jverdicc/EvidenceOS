import numpy as np
import matplotlib.pyplot as plt

plt.style.use('seaborn-v0_8-whitegrid')


def run_sybil_simulation(n_identities, topic_budget, seed=42) -> dict:
    np.random.seed(seed)

    # Directional proxy metrics: naive per-identity budgeting scales with identities,
    # while TopicHash enforces one shared budget over the topic.
    naive_success = float(np.clip((n_identities / float(topic_budget)) * 0.25, 0.0, 1.0))
    topichash_success = float(np.clip(0.001 * (float(topic_budget) / max(float(n_identities), 1.0)), 0.0, 1.0))

    freeze_identity = int(float(topic_budget)) + 1
    if n_identities >= freeze_identity:
        fifth_identity_status = 'FROZEN'
    else:
        fifth_identity_status = 'ACCEPT'

    return {
        'naive_success': naive_success,
        'topichash_success': topichash_success,
        'fifth_identity_status': fifth_identity_status,
    }


def run_demo(save_plot: bool = True):
    secret_bits = 20
    max_identities = 20
    topic_budget_bits = 4.0
    k_bits_per_identity = 1.0

    identity_counts = np.arange(1, max_identities + 1)

    unbounded_bits = identity_counts.astype(float)
    bounded_bits = np.minimum(identity_counts * k_bits_per_identity, topic_budget_bits)

    unbounded_success_prob = np.clip(2.0 ** -(secret_bits - unbounded_bits), 0.0, 1.0)
    bounded_success_prob = np.clip(2.0 ** -(secret_bits - bounded_bits), 0.0, 1.0)

    freeze_identity = int(topic_budget_bits / k_bits_per_identity) + 1

    if save_plot:
        fig, ax1 = plt.subplots(figsize=(10, 6))
        ax1.plot(
            identity_counts,
            bounded_bits,
            color='#1a5276',
            linewidth=2.5,
            label='EvidenceOS Bounded',
        )
        ax1.plot(
            identity_counts,
            unbounded_bits,
            linestyle='--',
            color='#c0392b',
            linewidth=2.5,
            label='Unbounded (Status Quo)',
        )
        ax1.axvline(
            x=freeze_identity,
            color='#e67e22',
            linewidth=2,
            linestyle='--',
            label='FROZEN',
        )
        ax1.set_xlabel('Number of Identities')
        ax1.set_ylabel('Bits Recovered')

        ax2 = ax1.twinx()
        ax2.plot(identity_counts, unbounded_success_prob, color='#c0392b', linestyle=':', linewidth=1.5)
        ax2.plot(identity_counts, bounded_success_prob, color='#1a5276', linestyle='-.', linewidth=1.5)
        ax2.set_ylabel('Success Probability (log scale)')
        ax2.set_yscale('log')

        ax1.annotate(
            'TopicHash collapses all identities to\none shared budget',
            xy=(freeze_identity, topic_budget_bits),
            xytext=(freeze_identity + 2, topic_budget_bits + 5),
            arrowprops={'arrowstyle': '->', 'color': '#e67e22'},
        )

        ax1.set_title('Demo 4: Sybil Extraction Attack with Shared Topic Budget')
        ax1.legend(loc='upper left')
        fig.tight_layout()
        plt.savefig('demo4.png', dpi=150, bbox_inches='tight')
        plt.close(fig)

    print(f'Demo 4 complete: FROZEN at identity {freeze_identity} of {max_identities}')
    return {
        'demo': '4',
        'freeze_point': f'Identity {freeze_identity}',
        'unbounded_final': f'{unbounded_bits[-1]:.0f} bits',
        'bounded_final': f'{bounded_bits[-1]:.0f} bits',
    }


if __name__ == '__main__':
    run_demo()
