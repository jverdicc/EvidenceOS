from demo1_leaderboard_gaming import run_demo as run_demo1
from demo2_clinical_phacking import run_demo as run_demo2
from demo3_trading_overfitting import run_demo as run_demo3
from demo4_sybil_attack import run_demo as run_demo4
from demo5_genomic_privacy import run_demo as run_demo5


def main():
    print('Running UVP empirical demonstrations...')
    results = [run_demo1(), run_demo2(), run_demo3(), run_demo4(), run_demo5()]

    print('\nDemo | Freeze Point | Unbounded Final | Bounded Final')
    print('-----|-------------|-----------------|---------------')
    for row in results:
        print(f"{row['demo']} | {row['freeze_point']} | {row['unbounded_final']} | {row['bounded_final']}")


if __name__ == '__main__':
    main()
