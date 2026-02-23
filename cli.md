# Vault Commands
```bash
# Create a new vault
phrase vault new personal

# List all vaults
phrase vault list

# Delete a vault
phrase vault rm personal

# Set default/active vault
phrase vault use personal
```

# Category Commands
```bash
# Create a new category
phrase category new work

# List categories in the active vault
phrase category list

# Delete a category
phrase category rm work

# Set default/active category
phrase category use work
```

# Entry (Credentials) Commands
```bash
# Create a new entry
phrase entry new gmail

# Get an entry
phrase entry get gmail

# Edit an entry
phrase entry edit gmail

# Delete an entry
phrase entry rm gmail

# Optional override if not in active category
phrase entry new github --category work
phrase entry get github --category work
```
