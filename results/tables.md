# TokenTaint results (auto-generated)

## Headline: security vs. utility

| Defense | Attack prevention ↑ | False-block rate ↓ | Prevention \| attempted ↑ |
|---|---|---|---|
| No defense | 0.138 | 0.000 | 0.000 |
| Classifier baseline | 0.535 | 0.165 | 0.461 |
| TokenTaint (structural) | 1.000 | 0.250 | 1.000 |
| TokenTaint (attribution) | 1.000 | 0.000 | 1.000 |
| TokenTaint (provenance-chain) | 1.000 | 0.000 | 1.000 |

## Attack-prevention rate by injection style

| Defense | Direct | Indirect | Obfuscated | Laundered |
|---|---|---|---|---|
| No defense | 0.06 | 0.10 | 0.17 | 0.22 |
| Classifier baseline | 0.94 | 0.69 | 0.21 | 0.30 |
| TokenTaint (structural) | 1.00 | 1.00 | 1.00 | 1.00 |
| TokenTaint (attribution) | 1.00 | 1.00 | 1.00 | 1.00 |
| TokenTaint (provenance-chain) | 1.00 | 1.00 | 1.00 | 1.00 |

## Tier-3: prevention vs. laundering effort

| Laundering effort | 0 | 1 | 2 | 3 | 4 |
|---|---|---|---|---|---|
| Structural | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| Attribution | 1.00 | 1.00 | 0.76 | 0.78 | 0.81 |
| Provenance-chain (new) | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
