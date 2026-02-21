import numpy as np
import matplotlib.pyplot as plt

np.random.seed(42)
plt.style.use('seaborn-v0_8-whitegrid')


def run_demo(save_plot: bool = True):
    n_individuals = 1000
    n_attributes = 20
    max_queries = 50
    joint_budget_bits = 16.0
    k_bits_per_query = 1.0

    _synthetic_attributes = np.random.randint(
        0,
        2,
        size=(n_individuals, n_attributes),
    )

    unbounded_pct = []
    bounded_pct = []

    k_total = 0.0
    freeze_query = None

    max_recoverable = min(n_individuals, 2 ** joint_budget_bits)
    pct_ceiling = (max_recoverable / n_individuals) * 100.0

    for query in range(1, max_queries + 1):
        records_exposed_unbounded = min(n_individuals, 2 ** (query * k_bits_per_query))
        unbounded_pct.append((records_exposed_unbounded / n_individuals) * 100.0)

        if freeze_query is None:
            k_total += k_bits_per_query
            if k_total > joint_budget_bits:
                freeze_query = query

        records_exposed_bounded = min(n_individuals, 2 ** min(k_total, joint_budget_bits))
        bounded_pct.append((records_exposed_bounded / n_individuals) * 100.0)

    freeze_for_plot = freeze_query if freeze_query is not None else max_queries

    if save_plot:
        x = np.arange(1, max_queries + 1)
        plt.figure(figsize=(10, 6))
        plt.plot(
            x,
            bounded_pct,
            color='#1a5276',
            linewidth=2.5,
            label='EvidenceOS Bounded',
        )
        plt.plot(
            x,
            unbounded_pct,
            linestyle='--',
            color='#c0392b',
            linewidth=2.5,
            label='Unbounded (Status Quo)',
        )
        plt.axvline(
            x=freeze_for_plot,
            color='#e67e22',
            linewidth=2,
            linestyle='--',
            label='FROZEN',
        )
        plt.axhline(
            y=pct_ceiling,
            color='gray',
            linewidth=2,
            linestyle=':',
            label='Privacy Ceiling',
        )
        plt.annotate(
            'Joint entropy budget enforces\nhard privacy ceiling',
            xy=(freeze_for_plot, pct_ceiling),
            xytext=(max(2, freeze_for_plot - 10), max(5, pct_ceiling - 20)),
            arrowprops={'arrowstyle': '->', 'color': 'gray'},
        )

        plt.title('Demo 5: Genomic Reconstruction Under Joint Entropy Budget')
        plt.xlabel('Query Count')
        plt.ylabel('Records De-anonymized (%)')
        plt.legend(loc='lower right')
        plt.tight_layout()
        plt.savefig('demo5.png', dpi=150, bbox_inches='tight')
        plt.close()

    print(f'Demo 5 complete: FROZEN at query {freeze_for_plot} of {max_queries}')
    return {
        'demo': '5',
        'freeze_point': f'Query {freeze_for_plot}',
        'unbounded_final': f'{unbounded_pct[-1]:.1f}% recovered',
        'bounded_final': f'{bounded_pct[-1]:.1f}% recovered',
    }


if __name__ == '__main__':
    run_demo()
