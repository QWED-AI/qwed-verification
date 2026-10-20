"""
QWED Benchmark Chart Generator

Creates a professional enterprise-grade visualization showing:
- Raw LLM (Claude Opus) accuracy in grey (risk)
- QWED-verified accuracy in green (safe)
- Critical gap annotation on Finance domain

For README and marketing materials.
"""

import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import matplotlib.pyplot as plt
import numpy as np
import os

# Data from QWED Benchmark Report (2024-12-22)
domains = ['Math\n(Basic)', 'Legal\nCompliance', 'Code\nSecurity', 'Adversarial\nPrompts', 'Hard\nLogic', 'Finance\nCalcs']
llm_accuracy = [100, 97.5, 92.5, 85.0, 80.0, 73.3]  # Claude Opus 4.5
qwed_accuracy = [100, 100, 100, 100, 100, 100]      # With QWED Verification

x = np.arange(len(domains))
width = 0.35

# Professional Style
plt.style.use('seaborn-v0_8-whitegrid')
fig, ax = plt.subplots(figsize=(14, 7), dpi=150)

# Colors
color_llm = '#7f8c8d'   # Grey (uncertainty)
color_qwed = '#00c853'  # QWED Green (trust)
color_risk = '#e74c3c'  # Red (danger)

# Plotting bars
rects1 = ax.bar(x - width/2, llm_accuracy, width, 
                label='Raw LLM (Claude Opus 4.5)', 
                color=color_llm, alpha=0.85,
                edgecolor='white', linewidth=1)
rects2 = ax.bar(x + width/2, qwed_accuracy, width, 
                label='With QWED Verification', 
                color=color_qwed, alpha=0.95,
                edgecolor='white', linewidth=1)

# Labels and title
ax.set_ylabel('Reliability Score (%)', fontsize=13, fontweight='bold', labelpad=10)
ax.set_xlabel('', fontsize=1)
ax.set_title('The Trust Gap: Raw LLM vs QWED Verification\n(215 Tests Across 7 Domains)', 
             fontsize=18, fontweight='bold', pad=20, color='#2c3e50')

ax.set_xticks(x)
ax.set_xticklabels(domains, fontsize=11, fontweight='medium')
ax.set_ylim(0, 120)
ax.set_xlim(-0.6, len(domains) - 0.4)

# Legend
ax.legend(loc='lower left', fontsize=11, framealpha=0.95)

# Grid
ax.yaxis.grid(True, linestyle='--', alpha=0.4)
ax.set_axisbelow(True)

# Remove top and right spines
ax.spines['top'].set_visible(False)
ax.spines['right'].set_visible(False)

# Add value labels on bars
def autolabel(rects, is_qwed=False):
    for rect in rects:
        height = rect.get_height()
        color = '#27ae60' if is_qwed else '#2c3e50'
        text = f'{height}%' if height < 100 else '100%'
        
        ax.annotate(text,
                    xy=(rect.get_x() + rect.get_width() / 2, height),
                    xytext=(0, 4),
                    textcoords="offset points",
                    ha='center', va='bottom',
                    fontsize=10, fontweight='bold', color=color)

autolabel(rects1)
autolabel(rects2, is_qwed=True)

# --- KILLER ANNOTATION: Finance Risk Gap ---
finance_idx = 5
ax.annotate('!! CRITICAL RISK\n27% Error Rate',
            xy=(finance_idx - width/2, 73.3), 
            xytext=(finance_idx - 1.8, 55),
            arrowprops=dict(arrowstyle='->', color=color_risk, lw=2),
            fontsize=12, color=color_risk, fontweight='bold',
            bbox=dict(boxstyle="round,pad=0.4", fc="white", ec=color_risk, lw=2))

# Add "QWED Catches All" annotation
ax.annotate('QWED: 100%\nAll 22 Errors Caught',
            xy=(finance_idx + width/2, 100), 
            xytext=(finance_idx - 0.5, 108),
            fontsize=11, color='#27ae60', fontweight='bold',
            bbox=dict(boxstyle="round,pad=0.3", fc="#e8f5e9", ec='#27ae60', lw=1.5))

# Add subtitle
plt.figtext(0.5, 0.02, 
            'QWED enables LLMs for production by providing deterministic verification | qwedai.tech',
            ha='center', fontsize=10, color='#7f8c8d', style='italic')

# Save
os.makedirs('docs-site/static/img', exist_ok=True)
output_path = 'docs-site/static/img/benchmark_chart.png'
plt.tight_layout(rect=[0, 0.05, 1, 1])
plt.savefig(output_path, bbox_inches='tight', facecolor='white', edgecolor='none')
print(f"Chart saved to {output_path}")

# Also save to benchmarks folder
output_path2 = 'benchmarks/benchmark_chart.png'
plt.savefig(output_path2, bbox_inches='tight', facecolor='white', edgecolor='none')
print(f"Chart also saved to {output_path2}")

print("Done!")
