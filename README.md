# Phrase

Phrase is a local-first password manager written in Rust.

No cloud. No accounts. Your vault stays on your machine.

![banner](https://raw.githubusercontent.com/0xRahim/phrase_cli/refs/heads/main/.useless/ss.png)

## Install
- Download Linux Binary From [Releases](https://github.com/0xRahim/phrase_cli/releases/tag/linux)
- Or Just Build Yourself
```bash
git clone https://github.com/0xRahim/phrase_cli.git
cd phrase_cli
cargo build --release
```

Binary:

```text
target/release/app
```

Optional:

```bash
sudo cp target/release/app /usr/local/bin/phrase
```

Then:

```bash
phrase --help
```

---

## Basic Usage

Create a vault:

```bash
$ phrase vault new <vault_name>
$ phrase vault new myvault
```

List vaults:

```bash
$ phrase vault list
```

Select a vault:

```bash
$ phrase vault use <vault_name>
$ phrase vault use myvault
```


Add a credential:

```bash
$ phrase cred new <alias> --category <category_name>
$ phrase cred new gmail # Default category is default
```

List credentials:

```bash
$ phrase cred list
```

Get a credential:

```bash
$ phrase cred get <alias>
$ phrase cred get gmail
```

Edit a credential:

```bash
$ phrase cred edit <alias>
$ phrase cred edit gmail
```

Remove a credential:

```bash
$ phrase cred rm gmail
```


---

## Security

* Credentials are encrypted before being stored
* Vaults are protected by your master password

---
<!--
## Documentation

* Wiki: [https://github.com/0xRahim/phrase_cli/wiki](https://github.com/0xRahim/phrase_cli/wiki)
* CLI notes: ./cli.md
* Security audit: [https://github.com/0xRahim/phrase_cli/tree/main/audits](https://github.com/0xRahim/phrase_cli/tree/main/audits)

-->
