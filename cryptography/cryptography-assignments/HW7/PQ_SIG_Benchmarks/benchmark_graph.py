import matplotlib.pyplot as plt
import numpy as np

# Data: (Label, κ, KeyGen, Sign, Verify) in ms
data = [
    # κ = 128
    ("Dilithium-2", 128, 0.135, 0.576, 0.141),
    ("SPHINCS+-Haraka-128f", 128, 4.955, 94.999, 6.331),
    ("SPHINCS+-Haraka-128s", 128, 254.446, 1923.072, 2.056),
    ("SPHINCS+-SHA2-128f", 128, 2.809, 53.443, 3.088),
    ("SPHINCS+-SHA2-128s", 128, 144.099, 1076.962, 1.063),
    ("SPHINCS+-SHAKE-128f", 128, 3.050, 70.644, 4.264),
    ("SPHINCS+-SHAKE-128s", 128, 192.863, 1464.463, 1.439),
    ("MUM-HORS", 128, 23901.868, 0.028817, 0.049736),
    ("TVPD-HORS", 128, 0.001245, 0.001209, 0.029272),
    
    # κ = 192
    ("Dilithium-3", 192, 0.247, 0.945, 0.234),
    ("SPHINCS+-Haraka-192f", 192, 5.509, 149.013, 8.206),
    ("SPHINCS+-Haraka-192s", 192, 339.573, 3426.385, 3.009),
    ("SPHINCS+-SHA2-192f", 192, 3.233, 84.383, 4.568),
    ("SPHINCS+-SHA2-192s", 192, 206.080, 1886.916, 1.591),
    ("SPHINCS+-SHAKE-192f", 192, 4.462, 114.499, 6.166),
    ("SPHINCS+-SHAKE-192s", 192, 285.758, 2573.086, 2.024),

    # κ = 256
    ("Dilithium-5", 256, 0.377, 1.140, 0.386),
    ("SPHINCS+-Haraka-256f", 256, 13.938, 316.279, 8.267),
    ("SPHINCS+-Haraka-256s", 256, 220.963, 3502.851, 4.728),
    ("SPHINCS+-SHA2-256f", 256, 8.620, 174.283, 4.676),
    ("SPHINCS+-SHA2-256s", 256, 136.679, 1669.882, 2.187),
    ("SPHINCS+-SHAKE-256f", 256, 11.712, 235.732, 6.398),
    ("SPHINCS+-SHAKE-256s", 256, 186.453, 2235.788, 3.039),
    ("XMSS-SHA2_10_256", 256, 4107.140, 5.840, 2.190),
]

metrics = ["Key Generation", "Sign", "Verify"]

# Plot separate graphs for each security level
for kappa in [128, 192, 256]:
    subset = [d for d in data if d[1] == kappa]
    labels = [d[0] for d in subset]
    
    keygen = [d[2] for d in subset]
    sign = [d[3] for d in subset]
    verify = [d[4] for d in subset]
    
    x = np.arange(len(labels))
    width = 0.25

    fig, ax = plt.subplots(figsize=(14,6))
    ax.bar(x - width, keygen, width, label='KeyGen')
    ax.bar(x, sign, width, label='Sign')
    ax.bar(x + width, verify, width, label='Verify')

    ax.set_yscale('log')
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=45, ha="right")
    ax.set_ylabel('Time [ms] (log scale)')
    ax.set_title(f'Post-Quantum Signature Performance (κ={kappa})')
    ax.legend()
    plt.tight_layout()
    plt.show()
