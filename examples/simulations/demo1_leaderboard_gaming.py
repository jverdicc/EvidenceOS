import numpy as np
import matplotlib.pyplot as plt

np.random.seed(42)
plt.style.use('seaborn-v0_8-whitegrid')


def run_demo(save_plot: bool = True):
    n_labels = 1000
    max_queries = 200
    k_budget = 47.0
    oracle_num_symbols = 2

    k_total = 0.0
    k_bits_per_query = float(np.log2(oracle_num_symbols))

    unbounded_acc = [50.0]
    bounded_acc = [50.0]

    current_correct_unbounded = n_labels // 2
    current_correct_bounded = n_labels // 2
    freeze_query = None

    for query in range(1, max_queries + 1):
        current_correct_unbounded = min(n_labels, current_correct_unbounded + 1)
        unbounded_acc.append((current_correct_unbounded / n_labels) * 100.0)

        if freeze_query is None:
            k_total += k_bits_per_query
            if k_total > k_budget:
                freeze_query = query
            else:
                current_correct_bounded = min(n_labels, current_correct_bounded + 1)
        bounded_acc.append((current_correct_bounded / n_labels) * 100.0)

    freeze_for_plot = freeze_query if freeze_query is not None else max_queries

    if save_plot:
        x = np.arange(0, max_queries + 1)
        plt.figure(figsize=(10, 6))
        plt.plot(
            x,
            bounded_acc,
            color='#1a5276',
            linewidth=2.5,
            label='EvidenceOS Bounded',
        )
        plt.plot(
            x,
            unbounded_acc,
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
        plt.annotate(
            f'FROZEN at query {freeze_for_plot}\nk budget exhausted',
            xy=(freeze_for_plot, bounded_acc[freeze_for_plot]),
            xytext=(freeze_for_plot + 12, bounded_acc[freeze_for_plot] + 6),
            arrowprops={'arrowstyle': '->', 'color': '#e67e22'},
            color='#7d6608',
        )
        plt.title('Demo 1: Leaderboard Gaming on a Private Benchmark')
        plt.xlabel('Query Number')
        plt.ylabel('Test Set Accuracy (%)')
        plt.legend()
        plt.tight_layout()
        plt.savefig('demo1.png', dpi=150, bbox_inches='tight')
        plt.close()

    print(f'Demo 1 complete: FROZEN at query {freeze_for_plot} of {max_queries}')
    return {
        'demo': '1',
        'freeze_point': f'Query {freeze_for_plot}',
        'unbounded_final': f'{unbounded_acc[-1]:.1f}% accuracy',
        'bounded_final': f'{bounded_acc[-1]:.1f}% accuracy',
    }


if __name__ == '__main__':
    run_demo()
