import numpy as np
import matplotlib.pyplot as plt

np.random.seed(42)
plt.style.use('seaborn-v0_8-whitegrid')


def _sharpe(returns: np.ndarray) -> float:
    std = np.std(returns)
    if std <= 1e-12:
        return 0.0
    return float(np.mean(returns) / std * np.sqrt(252))


def run_demo(save_plot: bool = True):
    n_price_points = 1000
    max_iterations = 100
    alpha = 0.05
    k_budget = 32.0
    oracle_num_symbols = 8

    k_total = 0.0
    k_bits_per_query = float(np.log2(oracle_num_symbols))

    prices = np.cumsum(np.random.normal(0.0, 1.0, n_price_points)) + 100.0

    unbounded_sharpes = []
    bounded_sharpes = []
    barriers = []

    best_bounded = 0.0
    freeze_iteration = None
    W = 1.0

    # barrier rises with k making certification harder; W growing slower than barrier means strategy cannot certify
    for iteration in range(1, max_iterations + 1):
        short_window = np.random.randint(2, 40)
        long_window = np.random.randint(50, 200)
        if short_window >= long_window:
            long_window = short_window + np.random.randint(5, 20)

        ma_short = np.convolve(prices, np.ones(short_window) / short_window, mode='valid')
        ma_long = np.convolve(prices, np.ones(long_window) / long_window, mode='valid')

        aligned = min(len(ma_short), len(ma_long))
        signal = (ma_short[-aligned:] > ma_long[-aligned:]).astype(float)
        rets = np.diff(prices[-(aligned + 1):]) / prices[-(aligned + 1):-1]
        strategy_rets = signal[:-1] * rets[:-1]

        split = max(10, int(0.7 * len(strategy_rets)))
        in_sample_sharpe = _sharpe(strategy_rets[:split])
        out_sample_sharpe = _sharpe(strategy_rets[split:])

        unbounded_candidate = max(unbounded_sharpes[-1], in_sample_sharpe) if unbounded_sharpes else in_sample_sharpe
        unbounded_sharpes.append(unbounded_candidate)

        e_value = max(0.01, out_sample_sharpe / max(0.01, in_sample_sharpe))
        W *= e_value

        k_total += k_bits_per_query
        certification_barrier = (2 ** k_total) / alpha
        barriers.append(certification_barrier)

        if freeze_iteration is None:
            if k_total > k_budget or e_value < (1.0 / certification_barrier):
                freeze_iteration = iteration
            else:
                best_bounded = max(best_bounded, in_sample_sharpe)

        bounded_sharpes.append(best_bounded)

    freeze_for_plot = freeze_iteration if freeze_iteration is not None else max_iterations

    if save_plot:
        x = np.arange(1, max_iterations + 1)
        fig, ax1 = plt.subplots(figsize=(10, 6))
        ax1.plot(
            x,
            bounded_sharpes,
            color='#1a5276',
            linewidth=2.5,
            label='EvidenceOS Bounded',
        )
        ax1.plot(
            x,
            unbounded_sharpes,
            linestyle='--',
            color='#c0392b',
            linewidth=2.5,
            label='Unbounded (Status Quo)',
        )
        ax1.axvline(
            x=freeze_for_plot,
            color='#e67e22',
            linewidth=2,
            linestyle='--',
            label='FROZEN',
        )
        ax1.set_xlabel('Iteration')
        ax1.set_ylabel('Sharpe Ratio')

        ax2 = ax1.twinx()
        ax2.plot(x, barriers, color='gray', linestyle=':', linewidth=2, label='Certification Barrier')
        ax2.set_ylabel('Certification Barrier (2^k / alpha)')
        ax2.set_yscale('log')

        ax1.set_title('Demo 3: Trading Overfitting vs UVP Certification Barrier')
        lines1, labels1 = ax1.get_legend_handles_labels()
        lines2, labels2 = ax2.get_legend_handles_labels()
        ax1.legend(lines1 + lines2, labels1 + labels2, loc='upper left')
        fig.tight_layout()
        plt.savefig('demo3.png', dpi=150, bbox_inches='tight')
        plt.close(fig)

    print(f'Demo 3 complete: FROZEN at iteration {freeze_for_plot} of {max_iterations}')
    return {
        'demo': '3',
        'freeze_point': f'Iteration {freeze_for_plot}',
        'unbounded_final': f'{unbounded_sharpes[-1]:.2f} Sharpe',
        'bounded_final': f'{bounded_sharpes[-1]:.2f} Sharpe',
    }


if __name__ == '__main__':
    run_demo()
