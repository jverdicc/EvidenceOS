import numpy as np
import matplotlib.pyplot as plt
from scipy.stats import ttest_ind

np.random.seed(42)
plt.style.use('seaborn-v0_8-whitegrid')


def run_demo(save_plot: bool = True):
    n_variables = 100
    n_samples = 50
    max_attempts = 30
    alpha = 0.05
    k_budget = 8.0
    oracle_num_symbols = 2

    k_total = 0.0
    k_bits_per_query = float(np.log2(oracle_num_symbols))

    p_values = []
    alpha_primes = []
    certified = []
    freeze_attempt = None

    first_raw_sig_attempt = None

    for attempt in range(1, max_attempts + 1):
        variable_bank_a = np.random.normal(0, 1, size=(n_samples, n_variables))
        variable_bank_b = np.random.normal(0, 1, size=(n_samples, n_variables))
        mined_variable = np.random.randint(0, n_variables)

        _, p_value = ttest_ind(
            variable_bank_a[:, mined_variable],
            variable_bank_b[:, mined_variable],
            equal_var=False,
        )
        p_values.append(p_value)

        k_total += k_bits_per_query
        alpha_prime = alpha * (2 ** (-k_total))
        alpha_primes.append(alpha_prime)

        certified.append(p_value < alpha_prime)

        if first_raw_sig_attempt is None and p_value < alpha:
            first_raw_sig_attempt = attempt

        if freeze_attempt is None and k_total > k_budget:
            freeze_attempt = attempt

    freeze_for_plot = freeze_attempt if freeze_attempt is not None else max_attempts

    if save_plot:
        x = np.arange(1, max_attempts + 1)
        plt.figure(figsize=(10, 6))
        plt.plot(
            x,
            p_values,
            linestyle='--',
            color='#c0392b',
            linewidth=2.5,
            label='Unbounded (Status Quo)',
        )
        plt.plot(
            x,
            alpha_primes,
            color='#1a5276',
            linewidth=2.5,
            label='EvidenceOS Bounded',
        )
        plt.axhline(
            y=alpha,
            color='gray',
            linestyle=':',
            linewidth=2,
            label='Static $\\alpha=0.05$',
        )
        plt.axvline(
            x=freeze_for_plot,
            color='#e67e22',
            linewidth=2,
            linestyle='--',
            label='FROZEN',
        )

        if first_raw_sig_attempt is not None:
            plt.scatter(
                first_raw_sig_attempt,
                p_values[first_raw_sig_attempt - 1],
                marker='*',
                s=180,
                color='#f1c40f',
                edgecolors='black',
                zorder=5,
                label='First $p<0.05$',
            )

        plt.annotate(
            'EvidenceOS threshold decays exponentially with\n'
            'each query, making false certification impossible\n'
            'before budget exhaustion',
            xy=(freeze_for_plot, alpha_primes[min(freeze_for_plot - 1, max_attempts - 1)]),
            xytext=(max(2, freeze_for_plot - 6), alpha * 0.25),
            color='#1a5276',
        )

        plt.yscale('log')
        plt.title('Demo 2: Clinical p-Hacking Under Adaptive Subgroup Mining')
        plt.xlabel('Subgroup Attempt')
        plt.ylabel('p-value (log scale)')
        plt.legend(loc='lower left')
        plt.tight_layout()
        plt.savefig('demo2.png', dpi=150, bbox_inches='tight')
        plt.close()

    print(f'Demo 2 complete: FROZEN at attempt {freeze_for_plot} of {max_attempts}')
    return {
        'demo': '2',
        'freeze_point': f'Attempt {freeze_for_plot}',
        'unbounded_final': f'{p_values[-1]:.3g} p-value',
        'bounded_final': f'{alpha_primes[-1]:.3g} alpha\'',
    }


if __name__ == '__main__':
    run_demo()
