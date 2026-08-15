# Testnet Guide

## Networks

| Payload chain | Execution network | USDC |
| --- | --- | --- |
| `ethereum` | Ethereum Sepolia | `0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238` |
| `base` | Base Sepolia | `0x036CbD53842c5426634e7929541eC2318f3dCF7e` |
| `arbitrum` | Arbitrum Sepolia | `0x75faf114eafb1BDbe2F0316DF893fd58CE46AA4d` |

USDC uses 6 decimals and is the only execution-fee token. The normal execution
flow transfers its calculated fee to the chain's VerifyingPaymaster in the same
UserOperation as the protocol action.

## Funding checklist

1. Resolve the smart wallet with `GET /wallet`.
2. Fund it with Circle faucet USDC on the matching chain.
3. Fund any protocol assets required by the intended action.
4. Run `POST /simulate`.
5. Execute and poll `GET /status/:id`.

Useful faucets:

1. ETH testnet faucet: `https://www.alchemy.com/faucets`
2. USDC testnet faucet: `https://faucet.circle.com`
