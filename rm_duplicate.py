with open("src/vault.rs", "r") as f:
    lines = f.readlines()

out = []
skip = False
for line in lines:
    if line.strip() == "#[test]" and "fn test_vault_dpop_key_mutex_poisoned()" in lines[lines.index(line) + 1]:
        # we have two of these, let's just use a state machine
        pass
